package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile string
	jsonOut bool
)

var rootCmd = &cobra.Command{
	Use:   "mgw",
	Short: "Mail Gateway — почтовый шлюз (MTA / Mail Security Gateway)",
	Long: `mgw — единый бинарник почтового шлюза Mail Gateway.

Copyright 2026 Кислов Роман Сергеевич. Лицензия Apache-2.0.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command.
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		return err
	}
	return nil
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "config.yaml", "путь к конфигурации")
	rootCmd.PersistentFlags().BoolVar(&jsonOut, "json", false, "вывод в JSON")

	rootCmd.AddCommand(serverCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(certCmd)
}
