package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/robfig/cron/v3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/woodleighschool/UpdateUserInfo/internal/config"
	"github.com/woodleighschool/UpdateUserInfo/internal/jamf"
	"github.com/woodleighschool/UpdateUserInfo/internal/sync"
	"github.com/woodleighschool/UpdateUserInfo/internal/user"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		slog.Error("Command execution failed", "error", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "updateuserinfo",
		Short: "Jamf Pro/LDAP Synchronisation Tool",
		Long:  "Syncs user information from LDAP to Jamf Pro",

		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSync()
		},
	}

	flags := cmd.Flags()
	flags.String("schedule", "", "cron schedule expression for automatic sync (e.g., '0 2 * * *' for daily at 2 AM)")
	flags.String("log-level", "info", "logging level: debug, info, warn, error")
	flags.String("users-to-ignore", "", "comma separated list of usernames to ignore when updating")
	flags.String("instance-domain", "", "Jamf Pro host (can also use JAMF_HOST env var)")
	flags.String("client-id", "", "Jamf Pro API client id (can also use JAMF_CLIENT_ID env var)")
	flags.String("client-secret", "", "Jamf Pro API client secret (can also use JAMF_CLIENT_SECRET env var)")
	flags.String("ldap-host", "", "Windows Active Directory host (can also use LDAP_HOST env var)")
	flags.String("ldap-username", "", "Windows Active Directory username (can also use LDAP_USERNAME env var)")
	flags.String("ldap-credentials", "", "Windows Active Directory password (can also use LDAP_CREDENTIALS env var)")
	flags.String("dry-run", "false", "Run without making any permanent changes")

	if err := viper.BindPFlag("users_to_ignore", flags.Lookup("users-to-ignore")); err != nil {
		panic(fmt.Sprintf("failed to bind users-to-ignore flag: %v", err))
	}
	if err := viper.BindPFlag("instance_domain", flags.Lookup("instance-domain")); err != nil {
		panic(fmt.Sprintf("failed to bind instance-domain flag: %v", err))
	}
	if err := viper.BindPFlag("client_id", flags.Lookup("client-id")); err != nil {
		panic(fmt.Sprintf("failed to bind client-id flag: %v", err))
	}
	if err := viper.BindPFlag("client_secret", flags.Lookup("client-secret")); err != nil {
		panic(fmt.Sprintf("failed to bind client-secret flag: %v", err))
	}
	if err := viper.BindPFlag("ldap_host", flags.Lookup("ldap-host")); err != nil {
		panic(fmt.Sprintf("failed to bind ldap-host flag: %v", err))
	}
	if err := viper.BindPFlag("ldap_username", flags.Lookup("ldap-username")); err != nil {
		panic(fmt.Sprintf("failed to bind ldap-username flag: %v", err))
	}
	if err := viper.BindPFlag("ldap_credentials", flags.Lookup("ldap-credentials")); err != nil {
		panic(fmt.Sprintf("failed to bind ldap-credentials flag: %v", err))
	}
	if err := viper.BindPFlag("schedule", flags.Lookup("schedule")); err != nil {
		panic(fmt.Sprintf("failed to bind schedule flag: %v", err))
	}
	if err := viper.BindPFlag("log_level", flags.Lookup("log-level")); err != nil {
		panic(fmt.Sprintf("failed to bind log-level flag: %v", err))
	}
	if err := viper.BindPFlag("dry_run", flags.Lookup("dry-run")); err != nil {
		panic(fmt.Sprintf("failed to bind dry-run flag: %v", err))
	}

	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	cmd.AddCommand(newVersionCmd())

	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("updateuserinfo %s\n", version)
			fmt.Printf("commit: %s\n", commit)
			fmt.Printf("built: %s\n", date)
		},
	}
}

func runSync() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	logger := setupLogging(cfg)

	logger.Info("UpdateUserInfo starting",
		"version", version,
		"log_level", cfg.LogLevel,
		"oneshot_mode", cfg.IsOneshot(),
	)

	ldapClient, err := user.CreateLDAPClient(cfg, logger)
	if err != nil {

	}

	jamfClient, err := jamf.NewClient(cfg, cfg.LogLevel, logger, ldapClient)
	if err != nil {

	}
	defer func() {
		if closeErr := jamfClient.Close(); closeErr != nil {
			logger.Warn("failed to close Jamf client", "error", closeErr)
		}
	}()
	buildings, err := jamfClient.GetBuildings()
	if err != nil {
		return fmt.Errorf("unable to get buildings from Jamf API: %w", err)
	}
	cfg.JamfBuildings = buildings

	departments, err := jamfClient.GetDepartments()
	if err != nil {
		return fmt.Errorf("unable to get departments from Jamf API: %w", err)
	}
	cfg.JamfDepartments = departments

	syncService := sync.NewService(jamfClient, cfg, logger)

	if cfg.IsOneshot() {
		logger.Info("Running sync once (oneshot mode)")
		return syncService.Sync()
	}

	logger.Info("Setting up scheduled sync", "schedule", cfg.SyncSchedule)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	c := cron.New()

	_, err = c.AddFunc(cfg.SyncSchedule, func() {
		logger.Info("Starting scheduled sync")
		if err := syncService.Sync(); err != nil {
			logger.Error("Scheduled sync failed", "error", err)
		} else {
			logger.Info("Scheduled sync completed successfully")
		}
	})
	if err != nil {
		return fmt.Errorf("failed to add cron job: %w", err)
	}

	c.Start()
	defer c.Stop()

	logger.Info("Scheduler started, waiting for signals...")

	<-ctx.Done()
	logger.Info("Shutdown signal received, stopping...")

	return nil
}

func setupLogging(cfg *config.Config) *slog.Logger {
	opts := &slog.HandlerOptions{
		Level: cfg.GetLogLevel(),
	}

	handler := slog.NewJSONHandler(os.Stdout, opts)
	logger := slog.New(handler)

	slog.SetDefault(logger)

	return logger
}
