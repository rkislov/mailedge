package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/rkislov/mailedge/internal/config"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Работа с конфигурацией",
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Создать пример config.yaml",
	RunE: func(cmd *cobra.Command, args []string) error {
		path := cfgFile
		if path == "" {
			path = "config.yaml"
		}
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("файл уже существует: %s", path)
		}
		if err := os.WriteFile(path, []byte(config.ExampleYAML()), 0o644); err != nil {
			return err
		}
		fmt.Println("создан", path)
		return nil
	},
}

var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Проверить конфигурацию",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		fmt.Println("OK:", cfgFile)
		fmt.Printf("  smtp: %v\n", cfg.Server.SMTP.Listen)
		fmt.Printf("  web:  %s\n", cfg.Server.Web.Listen)
		fmt.Printf("  data: %s\n", cfg.Storage.DataDir)
		return nil
	},
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Показать загруженную конфигурацию",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		b, err := yaml.Marshal(cfg)
		if err != nil {
			return err
		}
		fmt.Print(string(b))
		return nil
	},
}

func init() {
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configValidateCmd)
	configCmd.AddCommand(configShowCmd)
}
