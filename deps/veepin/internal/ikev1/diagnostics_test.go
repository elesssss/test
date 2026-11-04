package ikev1

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/wanan9999/veepin/internal/vlog"
)

func TestRetransmitDiagnosticsPreserveBudgetAndCiphertext(t *testing.T) {
	for _, state := range []sessionState{stWaitMM5, stWaitQM1, stWaitQM3} {
		t.Run(state.String(), func(t *testing.T) {
			var logs bytes.Buffer
			result := newCapture()
			failure := &net.OpError{Op: "write", Net: "udp4", Err: errors.New("synthetic send failure")}
			attempts := 0
			ciphertext := []byte("synthetic ciphertext")
			s := NewSession(Config{Role: Responder, Handler: result, Logger: vlog.Text(&logs), Send: func(b []byte, natt bool) error {
				attempts++
				if !bytes.Equal(b, ciphertext) || !natt {
					t.Error("retransmit changed ciphertext or NAT-T flag")
				}
				return failure
			}})
			defer s.Close()
			s.state, s.lastSent, s.lastSentNATT = state, ciphertext, true
			// A duplicate response resend must not reset or consume the timer's
			// retry budget, alter state, or repeat the error warning per packet.
			s.resendLast("duplicate request")
			s.resendLast("duplicate request")
			if s.retries != 0 || s.state != state {
				t.Fatal("duplicate send failure changed state or retry budget")
			}
			for range ikeMaxRetransmits + 1 {
				s.onRetransmitGeneration(s.timerGeneration)
			}
			select {
			case err := <-result.fail:
				if !strings.Contains(err.Error(), "exchange timed out") || !strings.Contains(err.Error(), "waiting="+state.String()) || !errors.Is(err, failure) {
					t.Fatalf("timeout lost stage or send cause: %v", err)
				}
			default:
				t.Fatal("bounded retry exhaustion did not fail")
			}
			if attempts != ikeMaxRetransmits+2 || strings.Count(logs.String(), "retransmit send failed") != 1 {
				t.Fatalf("wrong retry or log count: attempts=%d logs=%s", attempts, logs.String())
			}
		})
	}
}

func TestInitialSendErrorAndDiagnosticReset(t *testing.T) {
	failure := errors.New("synthetic initial failure")
	s := NewSession(Config{Handler: newCapture(), Send: func([]byte, bool) error { return failure }})
	defer s.Close()
	s.state = stWaitMM3
	err := s.transmit([]byte("synthetic packet"))
	if !errors.Is(err, failure) || !strings.Contains(err.Error(), "waiting=MM3") {
		t.Fatalf("initial send error lost cause or stage: %v", err)
	}
	s.advance()
	if s.lastSendError != nil || s.lastSent != nil {
		t.Fatal("accepted next message retained old send diagnostics")
	}
}

func TestTimeoutWithoutSendErrorIdentifiesWaitingStage(t *testing.T) {
	result := newCapture()
	s := NewSession(Config{Handler: result, Send: func([]byte, bool) error { return nil }})
	defer s.Close()
	s.state, s.lastSent = stWaitQM1, []byte("synthetic MM6")
	for range ikeMaxRetransmits + 1 {
		s.onRetransmitGeneration(s.timerGeneration)
	}
	err := <-result.fail
	if !strings.Contains(err.Error(), "waiting=QM1") || strings.Contains(err.Error(), "last send error") {
		t.Fatalf("timeout without a send failure misreported: %v", err)
	}
}
