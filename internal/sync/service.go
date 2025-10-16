package sync

import (
	"log/slog"
	"slices"

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
	if s.config.DryRun {
		s.logger.Info("DRY_RUN enabled, no changes will be permanently made")
	}
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

	var devicesChanged int
	for i := 0; i < len(devices); i++ {
		device := devices[i]
		if device.NeedsToUpdate() {
			if slices.Contains(s.config.UsersToIgnore, device.LDAPUser.Username) || slices.Contains(s.config.UsersToIgnore, device.JamfUser.Username) {
				s.logger.Info("Skipping user as they are in ignore list", "user", device.LDAPUser.Username, "device", device.Name)
			} else {
				if device.DeviceType == "macOS" {
					err = s.jamfClient.UpdateComputer(&device, s.config.DryRun)
					if err != nil {
						s.logger.Error("Unable to update user", "error", err)
					}
				} else {
					err = s.jamfClient.UpdateMobileDevice(&device, s.config.DryRun)
					if err != nil {
						s.logger.Error("Unable to update user", "error", err)
					}
				}
				devicesChanged++
			}
		}
	}

	s.logger.Debug("Total devices", "computers", len(computers), "mobileDevices", len(mobileDevices))
	s.logger.Debug("Updated devices", "devices", devicesChanged)
	s.logger.Info("Completed synchronisation")
	return nil
}
