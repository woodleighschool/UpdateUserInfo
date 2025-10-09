package user

import (
	"fmt"
	"log/slog"
	"strconv"

	"github.com/go-ldap/ldap/v3"
	"github.com/woodleighschool/UpdateUserInfo/internal/config"
)

const (
	disabledBit = int64(2)
)

type LDAPClient struct {
	Client *ldap.Conn
	Config *config.Config
	Logger *slog.Logger
}

type User struct {
	Disabled     bool   `json:"disabled"`
	Username     string `json:"username"`
	Building     string `json:"building"`
	BuildingID   string `json:"buildingId"`
	Department   string `json:"department"`
	DepartmentID string `json:"departmentId"`
	RealName     string `json:"real_name"`
	Email        string `json:"email"`
}

func (u *User) Equals(other *User) bool {
	if u.BuildingID == other.BuildingID && u.DepartmentID == other.DepartmentID && u.Username == other.Username && u.RealName == other.RealName && u.Email == other.Email {
		return true
	} else {
		return false
	}
}

func (l *LDAPClient) LookupBuildingDepartment(user *User) error {
	if user.Building != "" && user.Department != "" && user.BuildingID == "" && user.DepartmentID == "" {
		user.BuildingID = l.Config.JamfBuildings[user.Building]
		user.DepartmentID = l.Config.JamfDepartments[user.Department]
		return nil
	} else if user.Building == "" && user.Department == "" && user.BuildingID != "" && user.DepartmentID != "" {
		user.Building = reverseMapLookup(l.Config.JamfBuildings, user.BuildingID)
		user.Department = reverseMapLookup(l.Config.JamfDepartments, user.DepartmentID)
		return nil
	} else {
		return fmt.Errorf("User instance in unrecoverable state")
	}
}

func (l *LDAPClient) CreateUserFromComputer(username string, buildingID string, departmentID string, realName string, email string) (*User, error) {
	user := User{
		Username:     username,
		BuildingID:   buildingID,
		DepartmentID: departmentID,
		RealName:     realName,
		Email:        email,
	}
	err := l.LookupBuildingDepartment(&user)
	if err != nil {
		l.Logger.Error("Unable to fill out building/department information for user", "user", username, "buildingID", buildingID, "departmentID", departmentID)
		return nil, fmt.Errorf("Unable to create user")
	}
	return &user, nil
}

func (l *LDAPClient) CreateUserFromMobileDevice(username string, building string, department string, realName string, email string) (*User, error) {
	user := User{
		Username:   username,
		Building:   building,
		Department: department,
		RealName:   realName,
		Email:      email,
	}
	err := l.LookupBuildingDepartment(&user)
	if err != nil {
		l.Logger.Error("Unable to fill out building/department information for user", "user", username, "building", building, "department", department)
		return nil, fmt.Errorf("Unable to create user")
	}
	return &user, nil
}

func (l *LDAPClient) CreateUserFromLDAP(username string, building string, department string, realName string, email string, disabled bool) (*User, error) {
	if disabled {
		building = "Disabled"
		department = "Disabled"
	}
	user := User{
		Username:   username,
		Building:   building,
		Department: department,
		RealName:   realName,
		Email:      email,
	}
	err := l.LookupBuildingDepartment(&user)
	if err != nil {
		l.Logger.Error("Unable to fill out building/department information for user", "user", username, "building", building, "department", department)
		return nil, fmt.Errorf("Unable to create user")
	}
	return &user, nil
}

func CreateLDAPClient(cfg *config.Config, logger *slog.Logger) (*LDAPClient, error) {
	l, err := ldap.DialURL(cfg.LDAPHost)
	if err != nil {
		logger.Error("Unable to connect to Active Directory server", "server", cfg.LDAPHost)
		return nil, fmt.Errorf("Unable to create LDAP client")
	}

	err = l.Bind(cfg.LDAPUsername, cfg.LDAPCredentials)
	if err != nil {
		logger.Error("Unable to bind to Active Directory with provided credentials")
		return nil, fmt.Errorf("Unable to create LDAP client")
	}

	return &LDAPClient{
		Client: l,
		Config: cfg,
		Logger: logger,
	}, nil
}

func (l *LDAPClient) GetUserInfo(username string) (*User, error) {
	l.Logger.Debug("Getting user details from Active Directory", "username", username)

	searchRequest := ldap.NewSearchRequest(
		"dc=woodleighschool,dc=net",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(samAccountName="+username+")",
		[]string{"name", "mail", "samAccountName", "userAccountControl", "department", "Campus"},
		nil,
	)

	results, err := l.Client.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("Error looking up user in Active Directory")
	}

	userDisabled := false
	userAccountControl, err := strconv.ParseInt(results.Entries[0].GetAttributeValue("userAccountControl"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("Unable to convert userAccountControl to int64")
	}
	if userAccountControl&disabledBit != 0 {
		userDisabled = true
	}
	building := results.Entries[0].GetAttributeValue("Campus")
	department := results.Entries[0].GetAttributeValue("department")
	realName := results.Entries[0].GetAttributeValue("name")
	email := results.Entries[0].GetAttributeValue("mail")

	user, err := l.CreateUserFromLDAP(username, building, department, realName, email, userDisabled)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func reverseMapLookup(dataMap map[string]string, valueToFind string) string {
	for key, value := range dataMap {
		if valueToFind == value {
			return key
		}
	}
	return ""
}
