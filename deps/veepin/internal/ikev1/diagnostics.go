package ikev1

import "fmt"

// String describes the message needed to advance the exchange, not just the
// exchange family. This distinguishes an unanswered MM6 from an unanswered QM2.
func (state sessionState) String() string {
	switch state {
	case stInit:
		return "initial request"
	case stWaitMM2:
		return "MM2"
	case stWaitMM3:
		return "MM3"
	case stWaitMM4:
		return "MM4"
	case stWaitMM5:
		return "MM5"
	case stWaitMM6:
		return "MM6"
	case stWaitAM2:
		return "AM2"
	case stWaitAM3:
		return "AM3"
	case stWaitXAuthReq:
		return "XAuth request"
	case stWaitXAuthRep:
		return "XAuth reply"
	case stWaitXAuthSet:
		return "XAuth status"
	case stWaitXAuthAck:
		return "XAuth acknowledgement"
	case stWaitCfgReq:
		return "Mode-Config request"
	case stWaitCfgRep:
		return "Mode-Config reply"
	case stWaitQM1:
		return "QM1 (after MM6/phase-1 response)"
	case stWaitQM2:
		return "QM2"
	case stWaitQM3:
		return "QM3 (after QM2 response)"
	case stDone:
		return "established"
	case stFailed:
		return "failed"
	default:
		return fmt.Sprintf("state-%d", int(state))
	}
}
