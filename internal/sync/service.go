package sync

import (
	"log/slog"

	"github.com/woodleighschool/UpdateUserInfo/internals/jamf"
)

type Service struct {
	jamfClient jamf.Client
	logger     *slog.Logger
}

func NewService(jamfClient jamf.Client, logger *slog.Logger) *Service {
	return &Service{
		jamfClient: jamfClient,
		logger:     logger,
	}
}

func (s *Service) Sync() error {
	s.logger.Info("Starting sync process")

	var devices = [0]jamf.Device{}

	computers, err := s.jamfClient.GetComputers()
	if err != nil {
		s.logger.Error("Unable to get computers from Jamf", "error", err)
	} else {
		devices = append(devices, computers)
	}

	mobileDevices, err := s.jamfClient.GetMobileDevices()
	if err != nil {
		s.logger.Error("Unable to get mobile devices from Jamf", "error", err)
	} else {
		devices = append(devices, mobileDevices)
	}

	for i := 0; i < len(devices); i++ {
		device := devices[i]
		if device.NeedsToUpdate() {
			if device.DeviceType == "macOS" {
				s.jamfClient.UpdateComputer(device)
			} else {
				s.jamfClient.UpdateMobileDevice(device)
			}
		}
	}

	s.logger.Info("Completed synchronisation")
	return nil
}
