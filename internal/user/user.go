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
	Disabled     bool    `json:"disabled"`
	Username     string  `json:"username"`
	Building     string  `json:"building"`
	BuildingID   *string `json:"buildingId,omitempty"`
	Department   string  `json:"department"`
	DepartmentID *string `json:"departmentId,omitempty"`
	RealName     *string `json:"real_name,omitempty"`
	Email        *string `json:"email,omitempty"`
}

func (u *User) Equals(other *User) bool {
	if u.BuildingID != nil && other.BuildingID != nil {
		if *u.BuildingID != *other.BuildingID {
			return false
		}
	}

	if u.DepartmentID != nil && other.DepartmentID != nil {
		if *u.DepartmentID != *other.DepartmentID {
			return false
		}
	}

	if u.Username != other.Username {
		return false
	}

	if u.RealName != nil && other.RealName != nil {
		if *u.RealName != *other.RealName {
			return false
		}
	}

	if u.Email != nil && other.Email != nil {
		if *u.Email != *other.Email {
			return false
		}
	}

	return true
}

func (l *LDAPClient) LookupLocationInfoFromID(user *User) error {
	if user.BuildingID == nil {
		user.Building = "No building"
	} else {
		building, err := l.Config.GetBuildingFromID(*user.BuildingID)
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		user.Building = building.Name
	}
	if user.DepartmentID == nil {
		user.Department = "No department"
	} else {
		department, err := l.Config.GetDepartmentFromID(*user.DepartmentID)
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		user.Department = department.Name
	}

	return nil
}

func (l *LDAPClient) LookupLocationInfoFromName(user *User) error {
	if user.Building == "" {
		user.BuildingID = nil
	} else {
		building, err := l.Config.GetBuildingFromName(user.Building)
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		user.BuildingID = &building.ID
	}
	if user.Department == "" {
		user.DepartmentID = nil
	} else {
		department, err := l.Config.GetDepartmentFromName(user.Department)
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		user.DepartmentID = &department.ID
	}

	return nil
}

func (l *LDAPClient) CreateUserFromJamf(username *string, buildingID *string, departmentID *string, realName *string, email *string) (*User, error) {
	user := User{
		Username:     *username,
		BuildingID:   buildingID,
		DepartmentID: departmentID,
		RealName:     realName,
		Email:        email,
	}
	err := l.LookupLocationInfoFromID(&user)
	if err != nil {
		l.Logger.Error("Unable to fill out building/department information for user", "user", username, "buildingID", buildingID, "departmentID", departmentID)
		return nil, fmt.Errorf("unable to create user")
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
		RealName:   &realName,
		Email:      &email,
	}
	err := l.LookupLocationInfoFromName(&user)
	if err != nil {
		l.Logger.Error("Unable to fill out building/department information for user", "user", username, "building", building, "department", department)
		return nil, fmt.Errorf("unable to create user")
	}
	return &user, nil
}

func CreateLDAPClient(cfg *config.Config, logger *slog.Logger) (*LDAPClient, error) {
	l, err := ldap.DialURL(cfg.LDAPHost)
	if err != nil {
		logger.Error("Unable to connect to Active Directory server", "server", cfg.LDAPHost)
		return nil, fmt.Errorf("unable to create LDAP client")
	}

	err = l.Bind(cfg.LDAPUsername, cfg.LDAPCredentials)
	if err != nil {
		logger.Error("Unable to bind to Active Directory with provided credentials")
		return nil, fmt.Errorf("unable to create LDAP client")
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
	if err != nil || len(results.Entries) == 0 {
		return nil, fmt.Errorf("error looking up user in Active Directory")
	}

	userDisabled := false
	userAccountControl, err := strconv.ParseInt(results.Entries[0].GetAttributeValue("userAccountControl"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("unable to convert userAccountControl to int64")
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
