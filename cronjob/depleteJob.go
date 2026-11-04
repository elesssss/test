package cronjob

import (
	"github.com/alireza0/s-ui/logger"
	"github.com/alireza0/s-ui/service"
)

type DepleteJob struct{ service.ConfigService }

func NewDepleteJob() *DepleteJob { return new(DepleteJob) }

func (s *DepleteJob) Run() {
	if err := s.ConfigService.ReconcileDepletedClients(); err != nil {
		logger.Error("unable to reconcile depleted users: ", err)
	}
}
