package service

import (
	"time"

	"github.com/alireza0/s-ui/database"
	"gorm.io/gorm"
)

// Serialize periodic authentication changes with saves, maintenance and core
// restarts. Audit/storage errors restore the previous inbound configuration.
func (s *ConfigService) ReconcileDepletedClients() error {
	return s.changeClientTraffic(func(tx *gorm.DB) error {
		_, err := s.ClientService.depleteClientsAt(tx, time.Now().Unix())
		return err
	})
}

func (s *ConfigService) ResetTraffic() error {
	return s.changeClientTraffic(s.ClientService.resetAllClientsTrafficAt)
}

func (s *ConfigService) changeClientTraffic(change func(*gorm.DB) error) error {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	tx := database.GetDB().Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer tx.Rollback()
	before, err := s.snapshotRuntime(tx, "clients")
	if err != nil {
		return err
	}
	if err = change(tx); err != nil {
		return err
	}
	after, err := s.snapshotRuntime(tx, "clients")
	if err != nil {
		return err
	}
	if err = applyRuntimeChanges(runtimeChanges(before, after), func() error { return tx.Commit().Error }); err != nil {
		return err
	}
	LastUpdate.Store(time.Now().Unix())
	return nil
}
