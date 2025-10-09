package sync

import (
	"log/slog"

	"github.com/woodleighschool/UpdateUserInfo/internal/config"
	"github.com/woodleighschool/UpdateUserInfo/internal/jamf"
)

type Service struct {
	jamfClient jamf.Client
	config     *config.Config
	logger     *slog.Logger
}

func NewService(jamfClient jamf.Client, config *config.Config, logger *slog.Logger) *Service {
	return &Service{
		jamfClient: jamfClient,
		config:     config,
		logger:     logger,
	}
}

func (s *Service) Sync() error {
	s.logger.Info("Starting sync process")

	var devices []jamf.Device

	computers, err := s.jamfClient.GetComputers()
	if err != nil {
		s.logger.Error("Unable to get computers from Jamf", "error", err)
	} else {
		devices = append(devices, computers...)
	}

	mobileDevices, err := s.jamfClient.GetMobileDevices()
	if err != nil {
		s.logger.Error("Unable to get mobile devices from Jamf", "error", err)
	} else {
		devices = append(devices, mobileDevices...)
	}

	for i := 0; i < len(devices); i++ {
		device := devices[i]
		if device.NeedsToUpdate() {
			if device.DeviceType == "macOS" {
				s.jamfClient.UpdateComputer(&device, s.config.DryRun)
			} else {
				s.jamfClient.UpdateMobileDevice(&device, s.config.DryRun)
			}
		}
	}

	s.logger.Info("Completed synchronisation")
	return nil
}
