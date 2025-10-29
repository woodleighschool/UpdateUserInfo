package jamf

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"

	"github.com/woodleighschool/UpdateUserInfo/internal/config"
	"github.com/woodleighschool/UpdateUserInfo/internal/user"
	"github.com/woodleighschool/go-api-sdk-jamfpro/sdk/jamfpro"
)

type Device struct {
	ID         string     `json:"id"`
	DeviceType string     `json:"deviceType"`
	Name       string     `json:"name"`
	JamfUser   *user.User `json:"jamfUser"`
	LDAPUser   *user.User `json:"LDAPUser"`
}

type Client interface {
	GetBuildings() ([]config.JamfStructure, error)
	GetDepartments() ([]config.JamfStructure, error)
	GetComputers() ([]Device, error)
	GetMobileDevices() ([]Device, error)
	UpdateComputer(*Device, bool) error
	UpdateMobileDevice(*Device, bool) error
	Close() error
}

type jamfClient struct {
	client     *jamfpro.Client
	config     *config.Config
	ldapClient *user.LDAPClient
	logger     *slog.Logger
}

func NewClient(cfg *config.Config, logger *slog.Logger, ldapClient *user.LDAPClient) (Client, error) {
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
		config:     cfg,
		logger:     logger,
		ldapClient: ldapClient,
	}, nil
}

func (j *jamfClient) GetDepartments() ([]config.JamfStructure, error) {
	var departments []config.JamfStructure

	resp, err := j.client.GetDepartments(url.Values{})
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	for _, value := range resp.Results {
		departments = append(departments, config.JamfStructure{
			ID:   value.ID,
			Name: value.Name,
		})
	}

	departments = append(departments, config.JamfStructure{
		ID:   "-1",
		Name: "No department",
	})

	return departments, nil
}

func (j *jamfClient) GetBuildings() ([]config.JamfStructure, error) {
	var buildings []config.JamfStructure

	resp, err := j.client.GetBuildings(url.Values{})
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	for _, value := range resp.Results {
		buildings = append(buildings, config.JamfStructure{
			ID:   value.ID,
			Name: value.Name,
		})
	}

	buildings = append(buildings, config.JamfStructure{
		ID:   "-1",
		Name: "No building",
	})

	j.config.JamfBuildings = buildings
	return buildings, nil
}

func (j *jamfClient) GetComputers() ([]Device, error) {
	j.logger.Debug("Getting all macOS devices")

	params := url.Values{}
	params.Set("page-size", "5000")
	params.Set("section", "GENERAL")
	params.Add("section", "USER_AND_LOCATION")
	params.Set("filter", "general.remoteManagement.managed==true")

	resp, err := j.client.GetComputersInventory(params)
	if err != nil {
		j.logger.Error("Error getting macOS device list", "error", err)
		return nil, fmt.Errorf("failed to get macOS device list: %w", err)
	}

	var computers []Device
	for i := 0; i < resp.TotalCount; i++ {
		deviceResp := resp.Results[i]
		if deviceResp.UserAndLocation.Username == nil {
			j.logger.Debug("No user associated with device, skipping over", "device", deviceResp.General.Name)
			continue
		}

		jamfUser, err := j.ldapClient.CreateUserFromJamf(
			deviceResp.UserAndLocation.Username,
			deviceResp.UserAndLocation.BuildingId,
			deviceResp.UserAndLocation.DepartmentId,
			deviceResp.UserAndLocation.Realname,
			deviceResp.UserAndLocation.Email,
		)
		if err != nil {
			j.logger.Error("Unable to check device", "device", deviceResp.General.Name, "error", err)
			continue
		}

		ldapDetails, err := j.ldapClient.GetUserInfo(*deviceResp.UserAndLocation.Username)
		if err != nil {
			j.logger.Warn("Unable to get details from Active Directory for user", "user", deviceResp.UserAndLocation.Username)
			continue
		}

		device := Device{
			ID:         *deviceResp.ID,
			DeviceType: "macOS",
			Name:       *deviceResp.General.Name,
			JamfUser:   jamfUser,
			LDAPUser:   ldapDetails,
		}

		computers = append(computers, device)
	}

	return computers, nil
}

func (j *jamfClient) GetMobileDevices() ([]Device, error) {
	j.logger.Debug("Getting all iOS devices")

	params := url.Values{}
	params.Set("page-size", "5000")
	params.Set("section", "GENERAL")
	params.Add("section", "USER_AND_LOCATION")
	params.Set("filter", "managed==true")

	resp, err := j.client.GetMobileDevicesInventory(params)
	if err != nil {
		j.logger.Error("Error getting iOS device list", "error", err)
		return nil, fmt.Errorf("failed to get iOS device list: %w", err)
	}

	var devices []Device
	for i := 0; i < len(resp.Results); i++ {
		deviceResp := resp.Results[i]
		if *deviceResp.UserAndLocation.Username == "" {
			j.logger.Debug("No user assocaited with device, skipping over", "device", *deviceResp.General.DisplayName)
			continue
		}

		jamfUser, err := j.ldapClient.CreateUserFromJamf(
			deviceResp.UserAndLocation.Username,
			deviceResp.UserAndLocation.BuildingID,
			deviceResp.UserAndLocation.DepartmentID,
			deviceResp.UserAndLocation.RealName,
			deviceResp.UserAndLocation.EmailAddress,
		)
		if err != nil {
			j.logger.Error("Unable to check device", "device", *deviceResp.General.DisplayName, "error", err)
			continue
		}

		ldapDetails, err := j.ldapClient.GetUserInfo(*deviceResp.UserAndLocation.Username)
		if err != nil {
			j.logger.Warn("Unable to get details from Active Directory for user", "user", *deviceResp.UserAndLocation.Username)
			continue
		}

		device := Device{
			ID:         *deviceResp.MobileDeviceID,
			DeviceType: "iOS",
			Name:       *deviceResp.General.DisplayName,
			JamfUser:   jamfUser,
			LDAPUser:   ldapDetails,
		}

		devices = append(devices, device)
	}

	return devices, nil
}

func (j *jamfClient) UpdateComputer(device *Device, dryRun bool) error {
	if !dryRun {
		payload := jamfpro.ResourceComputerInventory{
			UserAndLocation: &jamfpro.ComputerInventorySubsetUserAndLocation{
				Username:     &device.LDAPUser.Username,
				Realname:     device.LDAPUser.RealName,
				Email:        device.LDAPUser.Email,
				DepartmentId: device.LDAPUser.DepartmentID,
				BuildingId:   device.LDAPUser.BuildingID,
			},
		}
		_, err := j.client.UpdateComputerInventoryByID(device.ID, &payload)
		if err != nil {
			return fmt.Errorf("failed to update computer info: %w", err)
		}
	}
	j.logger.Info("Updated user and location information", "device", device.Name, "user", device.LDAPUser.Username, "oldBuilding", device.JamfUser.Building, "oldDepartment", device.JamfUser.Department, "building", device.LDAPUser.Building, "department", device.LDAPUser.Department)
	return nil
}

func (j *jamfClient) UpdateMobileDevice(device *Device, dryRun bool) error {
	if !dryRun {
		payload := jamfpro.UpdateMobileDeviceInventory{
			Location: &jamfpro.MobileDeviceInventorySubsetUserAndLocation{
				Username:     &device.LDAPUser.Username,
				RealName:     device.LDAPUser.RealName,
				EmailAddress: device.LDAPUser.Email,
				DepartmentID: device.LDAPUser.DepartmentID,
				BuildingID:   device.LDAPUser.BuildingID,
			},
		}
		_, err := j.client.UpdateMobileDeviceInventoryByID(device.ID, &payload)
		if err != nil {
			return fmt.Errorf("failed to update mobile device info: %w", err)
		}
	}

	j.logger.Info("Updated user and location information", "device", device.Name, "user", device.LDAPUser.Username, "oldBuilding", device.JamfUser.Building, "oldDepartment", device.JamfUser.Department, "building", device.LDAPUser.Building, "department", device.LDAPUser.Department)
	return nil
}

func (j *jamfClient) Close() error {
	return nil
}

func (d *Device) NeedsToUpdate() bool {
	return !d.JamfUser.Equals(d.LDAPUser)
}
