package l2tp

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// CallHandler is the server-side multi-call API. Handler remains the single
// call client API. Both use Tunnel's one reliable control sequence/window.
type CallHandler interface {
	CallUp(localID uint16)
	CallData(localID uint16, frame []byte)
	CallClosed(localID uint16, err error)
	Closed(error)
}

type tunnelCall struct {
	localID, peerID               uint16
	up, closed                    bool
	closedUntil                   time.Time
	created                       time.Time
	requireSequence, sequenceData bool
	dataNS, dataNR                uint16
}

type callEvent struct {
	id  uint16
	up  bool
	err error
}

const maxCallsPerTunnel = 512 // includes pending calls and bounded tombstones

func NewServerTunnel(send func([]byte) error, h CallHandler) *Tunnel {
	t := NewTunnel(RoleLNS, send, nil)
	t.callHandler = h
	t.calls = make(map[uint16]*tunnelCall)
	return t
}

func (t *Tunnel) SendCallPPP(id uint16, frame []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	call := t.calls[id]
	if t.state != stateEstablished || call == nil || !call.up || call.closed {
		return fmt.Errorf("l2tp: call %d is not up", id)
	}
	tid := uint16(t.peerTunnelID.Load())
	if !call.sequenceData {
		return t.send(marshalData(tid, call.peerID, frame))
	}
	out := make([]byte, 10+len(frame))
	out[0], out[1] = flagSeq, protocolVersion
	binary.BigEndian.PutUint16(out[2:], tid)
	binary.BigEndian.PutUint16(out[4:], call.peerID)
	binary.BigEndian.PutUint16(out[6:], call.dataNS)
	call.dataNS++
	copy(out[10:], frame)
	return t.send(out)
}

// A PPP transport tied to one Session ID, never the whole IPsec peer.
type callTransport struct {
	tunnel *Tunnel
	id     uint16
}

func (c callTransport) SendPPP(frame []byte) error { return c.tunnel.SendCallPPP(c.id, frame) }

func (t *Tunnel) closeCallLocked(call *tunnelCall, err error) {
	if call.closed {
		return
	}
	call.closed, call.up = true, false
	call.closedUntil = time.Now().Add(31 * time.Second)
	t.callEvents = append(t.callEvents, callEvent{id: call.localID, err: err})
}

func (t *Tunnel) queueCallDisconnect(call *tunnelCall) {
	var b avpBuilder
	b.addUint16(avpMessageType, msgCDN)
	b.add(avpResultCode, []byte{0, 1, 0, 0})
	b.addUint16(avpAssignedSessionID, call.localID)
	t.queueControl(call.peerID, b.bytes())
}

func (t *Tunnel) CloseCall(id uint16, err error) {
	t.mu.Lock()
	call := t.calls[id]
	if t.state != stateClosed && call != nil && !call.closed {
		t.queueCallDisconnect(call)
		t.closeCallLocked(call, err)
	}
	t.mu.Unlock()
	t.deliverCallEvents()
}

// One dispatcher preserves ICCN/CDN event order without holding the protocol
// lock across callbacks. A callback may synchronously CloseCall again.
func (t *Tunnel) deliverCallEvents() {
	t.mu.Lock()
	if t.callEventsDispatching {
		t.mu.Unlock()
		return
	}
	t.callEventsDispatching = true
	for len(t.callEvents) > 0 {
		event := t.callEvents[0]
		t.callEvents = t.callEvents[1:]
		t.mu.Unlock()
		if event.up {
			t.callHandler.CallUp(event.id)
		} else {
			t.callHandler.CallClosed(event.id, event.err)
		}
		t.mu.Lock()
	}
	t.callEvents = nil
	t.callEventsDispatching = false
	t.mu.Unlock()
}

func (t *Tunnel) acceptCallData(h header) {
	t.mu.Lock()
	call := t.calls[h.sessionID]
	valid := t.state == stateEstablished && h.tunnelID == t.localTunnelID && call != nil && call.up && !call.closed && len(h.payload) > 0
	if !valid {
		t.mu.Unlock()
		return
	}
	if h.hasSeq {
		if seqLess(h.ns, call.dataNR) {
			t.mu.Unlock()
			return
		}
		call.dataNR = h.ns + 1
		call.sequenceData = true
	} else if !call.requireSequence {
		call.sequenceData = false
	}
	id := call.localID
	t.mu.Unlock()
	t.callHandler.CallData(id, h.payload)
}

// Called under the control lock after AVP/sequence validation.
func (t *Tunnel) dispatchServerCalls(mt uint16, h header, avps []avp) error {
	switch mt {
	case msgICRQ:
		if t.state != stateEstablished {
			return nil
		}
		peerID, _ := findUint16(avps, avpAssignedSessionID)
		for _, call := range t.calls {
			if call.peerID != peerID {
				continue
			}
			if !call.closed {
				return nil
			} // Do not disconnect a live sibling on a duplicate request.
			for _, message := range t.unacked {
				if message.sessionID == peerID {
					return nil
				} // Old CDN must be acknowledged before peer-ID reuse.
			}
		}
		id := randID()
		for attempts := 0; t.calls[id] != nil; attempts++ {
			if attempts >= 65535 {
				return fmt.Errorf("l2tp: session ID space exhausted")
			}
			id++
			if id == 0 {
				id = 1
			}
		}
		if len(t.calls) >= maxCallsPerTunnel {
			var b avpBuilder
			b.addUint16(avpMessageType, msgCDN)
			b.add(avpResultCode, []byte{0, 2, 0, 4}) // general error: insufficient resources
			b.addUint16(avpAssignedSessionID, id)
			t.queueControl(peerID, b.bytes())
			return nil
		}
		call := &tunnelCall{localID: id, peerID: peerID, created: time.Now()}
		t.calls[id] = call
		var b avpBuilder
		b.addUint16(avpMessageType, msgICRP)
		b.addUint16(avpAssignedSessionID, id)
		t.queueControl(peerID, b.bytes())
	case msgICCN:
		call := t.calls[h.sessionID]
		if call == nil || call.closed || call.up {
			return nil
		}
		_, required := findAVP(avps, avpSequencingRequired)
		call.requireSequence, call.sequenceData = required, required
		call.up = true
		t.callEvents = append(t.callEvents, callEvent{id: call.localID, up: true})
	case msgCDN:
		call := t.calls[h.sessionID]
		if call == nil || call.closed {
			return nil
		}
		peerID, _ := findUint16(avps, avpAssignedSessionID)
		if peerID != call.peerID {
			return fmt.Errorf("l2tp: CDN peer session ID mismatch")
		}
		t.closeCallLocked(call, io.EOF)
	case 16: // Set-Link-Info belongs to this call; synchronous PPP ignores ACCM.
	}
	return nil
}
