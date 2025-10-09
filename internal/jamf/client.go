package jamf

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"

	"github.com/deploymenttheory/go-api-sdk-jamfpro/sdk/jamfpro"
	"github.com/woodleighschool/UpdateUserInfo/internal/config"
	"github.com/woodleighschool/UpdateUserInfo/internal/user"
)

type Device struct {
	ID         int        `json:"id"`
	DeviceType string     `json:"deviceType"`
	Name       string     `json:"name"`
	JamfUser   *user.User `json:"jamfUser"`
	LDAPUser   *user.User `json:"LDAPUser"`
}

type Client interface {
	GetComputers() ([]Device, error)
	GetMobileDevices() ([]Device, error)
	UpdateComputer(device *Device) error
	UpdateMobileDevice(device *Device) error
	Close() error
}

type jamfClient struct {
	client     *jamfpro.Client
	ldapClient *user.LDAPClient
	logger     *slog.Logger
}

func NewClient(cfg *config.Config, logLevel string, logger *slog.Logger, ldapClient *user.LDAPClient) (Client, error) {
	if err := os.Setenv("INSTANCE_DOMAIN", cfg.InstanceDomain); err != nil {
		return nil, fmt.Errorf("failed to set INSTANCE_DOMAIN environment variable: %w", err)
	}
	if err := os.Setenv("CLIENT_ID", cfg.ClientID); err != nil {
		return nil, fmt.Errorf("failed to set CLIENT_ID environment variable: %w", err)
	}
	if err := os.Setenv("CLIENT_SECRET", cfg.ClientSecret); err != nil {
		return nil, fmt.Errorf("failed to set CLIENT_SECRET environment variable: %w", err)
	}
	if err := os.Setenv("AUTH_METHOD", cfg.AuthMethod); err != nil {
		return nil, fmt.Errorf("failed to set AUTH_METHOD environment variable: %w", err)
	}
	if err := os.Setenv("TOKEN_REFRESH_BUFFER_PERIOD_SECONDS", cfg.TokenRefreshBufferPeriod); err != nil {
		return nil, fmt.Errorf("failed to set TOKEN_REFRESH_BUFFER_PERIOD_SECONDS environment variable: %w", err)
	}
	if err := os.Setenv("TOKEN_BUFFER_PERIOD_SECONDS", cfg.TokenBufferPeriod); err != nil {
		return nil, fmt.Errorf("failed to set TOKEN_BUFFER_PERIOD_SECONDS environment variable: %w", err)
	}

	if err := os.Setenv("LOG_LEVEL", "fatal"); err != nil {
		return nil, fmt.Errorf("failed to set LOG_LEVEL environment variable: %w", err)
	}

	client, err := jamfpro.BuildClientWithEnv()
	if err != nil {
		return nil, fmt.Errorf("failed to initalise Jamf Pro client: %w", err)
	}

	return &jamfClient{
		client:     client,
		logger:     logger,
		ldapClient: ldapClient,
	}, nil
}

func (j *jamfClient) GetComputers() ([]Device, error) {
	j.logger.Debug("Getting all macOS devices")

	params := url.Values{}
	params.Set("page-size", "5000")
	params.Set("filter", "managed==true")

	resp, err := j.client.GetComputersInventory(params)
	if err != nil {
		j.logger.Error("Error getting macOS device list", "error", err)
		return nil, fmt.Errorf("failed to get macOS device list: %w", err)
	}

	var computers []Device
	for i := 0; i < resp.TotalCount; i++ {
		deviceResp := resp.Results[i]
		if deviceResp.UserAndLocation.Username == "" {
			j.logger.Info("No user associated with device, skipping over", "device", deviceResp.General.Name)
		}

		jamfUser, err := j.ldapClient.CreateUserFromMobileDevice(
			deviceResp.UserAndLocation.Username,
			deviceResp.UserAndLocation.BuildingId,
			deviceResp.UserAndLocation.DepartmentId,
			deviceResp.UserAndLocation.Realname,
			deviceResp.UserAndLocation.Email,
		)
		if err != nil {
			j.logger.Error("Unable to check device", "device", deviceResp.General.Name, "error", err)
		}

		ldapDetails, err := j.ldapClient.GetUserInfo(deviceResp.UserAndLocation.Username)
		if err != nil {
			j.logger.Error("Error getting details from Active Directory for user", "user", deviceResp.UserAndLocation.Username)
			continue
		}

		device := Device{
			ID:         deviceResp.ID,
			DeviceType: "macOS",
			Name:       deviceResp.General.Name,
			JamfUser:   jamfUser,
			LDAPUser:   ldapDetails,
		}

		computers = append(computers, device)
	}

	return computers, nil
}

func (j *jamfClient) GetMobileDevices() ([]Device, error) {
	j.logger.Debug("Getting all iOS devices")

	resp, err := j.client.GetMobileDevices()
	if err != nil {
		j.logger.Error("Error getting iOS device list", "error", err)
		return nil, fmt.Errorf("failed to get iOS device list: %w", err)
	}

	var devicesToProbe []int
	var devices []Device
	for i := 0; i < len(resp.MobileDevices); i++ {
		deviceResp := resp.MobileDevices[i]
		if !deviceResp.Managed {
			j.logger.Debug("Device not managed, skipping over", "device", deviceResp.Name)
		}
		if deviceResp.Username == "" {
			j.logger.Info("No user associated with device, skipping over", "device", deviceResp.Name)
		}
		devicesToProbe = append(devicesToProbe, deviceResp.ID)
	}

	for i := 0; i < len(devicesToProbe); i++ {
		resp, err := j.client.GetMobileDeviceByID(string(devicesToProbe[i]))
		if err != nil {
			j.logger.Error("Error getting details for iOS device", "deviceID", devicesToProbe[i], "error", err)
			continue
		}

		jamfUser, err := j.ldapClient.CreateUserFromMobileDevice(
			resp.Location.Username,
			resp.Location.Building,
			resp.Location.Department,
			resp.Location.RealName,
			resp.Location.Email,
		)
		if err != nil {
			j.logger.Error("Error checking device", "device", resp.General.Name, "error", err)
		}

		ldapDetails, err := j.ldapClient.GetUserInfo(resp.UserAndLocation.Username)
		if err != nil {
			j.logger.Error("Error getting details from Active Directory for user", "user", resp.UserAndLocation.Username)
			continue
		}

		device := Device{
			ID:         resp.General.ID,
			DeviceType: "iOS",
			Name:       resp.General.Name,
			JamfUser:   jamfUser,
			LDAPUser:   ldapDetails,
		}

		devices = append(devices, device)
	}

	return devices, nil
}

func (j *jamfClient) UpdateComputer(device *Device) error {
	return nil
}

func (j *jamfClient) UpdateMobileDevice(device *Device) error {
	return nil
}

func (j *jamfClient) Close() error {
	return nil
}

func (d *Device) NeedsToUpdate() bool {
	return d.JamfUser.Equals(d.LDAPUser)
}
