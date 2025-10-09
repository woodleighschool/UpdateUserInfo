package config

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	InstanceDomain           string `mapstructure:"instance_domain"`
	ClientID                 string `mapstructure:"client_id"`
	ClientSecret             string `mapstructure:"client_secret"`
	AuthMethod               string `mapstructure:"auth_method"`
	TokenRefreshBufferPeriod string `mapstructure:"token_refresh_buffer_period_seconds"`
	TokenBufferPeriod        string `mapstructure:"token_buffer_period_seconds"`

	JamfDepartments map[string]string `mapstructure:"departments"`
	JamfBuildings   map[string]string `mapstructure:"buildings"`

	LDAPHost        string `mapstructure:"ldap_host"`
	LDAPUsername    string `mapstructure:"ldap_username"`
	LDAPCredentials string `mapstructure:"ldap_credentials"`

	SyncSchedule string `mapstructure:"sync_schedule"`
	LogLevel     string `mapstructure:"log_level"`
	DryRun       bool   `mapstructure:"dry_run"`
}

func Load() (*Config, error) {
	v := viper.GetViper()

	v.SetDefault("auth_method", "oauth2")
	v.SetDefault("token_refresh_buffer_period_seconds", "5")
	v.SetDefault("token_buffer_period_seconds", "10")
	v.SetDefault("sync_schedule", "")
	v.SetDefault("log_level", "info")
	v.SetDefault("dry_run", false)

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	var errors []string

	if c.InstanceDomain == "" {
		errors = append(errors, "INSTANCE_DOMAIN is required")
	} else {
		if !strings.HasPrefix(c.InstanceDomain, "http://") && !strings.HasPrefix(c.InstanceDomain, "https://") {
			c.InstanceDomain = "https://" + c.InstanceDomain
		}
	}

	if c.ClientID == "" {
		errors = append(errors, "CLIENT_ID is required")
	}
	if c.ClientSecret == "" {
		errors = append(errors, "CLIENT_SECRET is required")
	}

	if c.LDAPHost == "" {
		errors = append(errors, "LDAP_HOST is required")
	} else {
		if !strings.HasPrefix(c.LDAPHost, "ldap://") {
			c.LDAPHost = "ldap://" + c.LDAPHost
		}
	}

	if c.LDAPUsername == "" {
		errors = append(errors, "LDAP_USERNAME is required")
	} else {
		if !strings.Contains(c.LDAPUsername, `\\`) {
			errors = append(errors, `LDAP_USERNAME must be in the format 'domain\\username'`)
		}
	}
	if c.LDAPCredentials == "" {
		errors = append(errors, "LDAP_CREDENTIALS is required")
	}

	validLogLevels := []string{"debug", "info", "warn", "error"}
	levelValid := false
	for _, level := range validLogLevels {
		if strings.ToLower(c.LogLevel) == level {
			levelValid = true
			break
		}
	}
	if !levelValid {
		errors = append(errors, fmt.Sprintf("LOG_LEVEL must be one of: %s", strings.Join(validLogLevels, ", ")))
	}

	if c.SyncSchedule != "" {
		parts := strings.Fields(c.SyncSchedule)
		if len(parts) != 5 {
			errors = append(errors, "SYNC_SCHEDULE must be a valid cron expression (5 fields) or empty for oneshot mode")
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("validation errors:\n - %s", strings.Join(errors, "\n - "))
	}

	return nil
}

func (c *Config) GetLogLevel() slog.Level {
	switch strings.ToLower(c.LogLevel) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func (c *Config) GetTimeout() time.Duration {
	return 5 * time.Minute
}

func (c *Config) IsOneshot() bool {
	return c.SyncSchedule == ""
}
