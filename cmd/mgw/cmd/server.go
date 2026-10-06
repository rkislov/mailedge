package cmd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/rkislov/mailedge/internal/config"
	"github.com/rkislov/mailedge/internal/server"
	"github.com/rkislov/mailedge/internal/version"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Управление процессом mgw",
}

var serverStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Запустить SMTP и веб-слушатели",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		app, err := server.New(cfg)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return app.Run(ctx)
	},
}

var serverStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Проверить доступность веб-эндпоинта и портов",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			// Fall back to probing defaults if config missing.
			st := map[string]any{
				"running": false,
				"version": version.Version,
				"error":   err.Error(),
			}
			return printStatus(st)
		}
		webOK := false
		client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // status probe only
		}}
		scheme := "http"
		if cfg.Server.Web.TLS {
			scheme = "https"
		}
		resp, err := client.Get(scheme + "://" + cfg.Server.Web.Listen + "/healthz")
		if err == nil {
			webOK = resp.StatusCode == 200
			_ = resp.Body.Close()
		}
		smtpOpen := false
		for _, addr := range cfg.Server.SMTP.Listen {
			if server.IsPortOpen(addr) {
				smtpOpen = true
				break
			}
		}
		st := map[string]any{
			"running":     webOK || smtpOpen,
			"version":     version.Version,
			"web_listen":  cfg.Server.Web.Listen,
			"web_ok":      webOK,
			"smtp_listen": cfg.Server.SMTP.Listen,
			"smtp_ok":     smtpOpen,
			"hostname":    cfg.Server.SMTP.Hostname,
		}
		return printStatus(st)
	},
}

var serverVersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Показать версию",
	RunE: func(cmd *cobra.Command, args []string) error {
		if jsonOut {
			return printStatus(map[string]any{"version": version.Version})
		}
		fmt.Println(version.Version)
		return nil
	},
}

func printStatus(v any) error {
	if jsonOut {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func init() {
	serverCmd.AddCommand(serverStartCmd)
	serverCmd.AddCommand(serverStatusCmd)
	serverCmd.AddCommand(serverVersionCmd)
}
