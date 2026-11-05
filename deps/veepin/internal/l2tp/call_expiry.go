package l2tp

import "time"

// Reap call setup and tombstones independently of other users in the tunnel.
// IDs are retained through the close retry cycle and cannot be reused while a
// queued CDN still refers to them.
func (t *Tunnel) expireCalls(now time.Time) {
	t.mu.Lock()
	for id, call := range t.calls {
		if !call.closed && !call.up && now.Sub(call.created) >= time.Minute {
			t.queueCallDisconnect(call)
			t.closeCallLocked(call, ErrControlTimeout)
		}
		if call.closed && !now.Before(call.closedUntil) {
			pending := false
			for _, message := range t.unacked {
				if message.sessionID == call.peerID {
					pending = true
					break
				}
			}
			if !pending {
				delete(t.calls, id)
			}
		}
	}
	t.mu.Unlock()
	t.deliverCallEvents()
}
