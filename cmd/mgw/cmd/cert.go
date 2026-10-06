package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/rkislov/mailedge/internal/certs"
	"github.com/rkislov/mailedge/internal/config"
)

var certCmd = &cobra.Command{
	Use:   "cert",
	Short: "Управление SSL/TLS сертификатами, УЦ и ACME",
}

var (
	certImportCert string
	certImportKey  string
	certImportName string
	certDomains    []string
	certCAName     string
)

var certListCmd = &cobra.Command{
	Use:   "list",
	Short: "Список сертификатов в хранилище",
	RunE: func(cmd *cobra.Command, args []string) error {
		m, err := openCerts()
		if err != nil {
			return err
		}
		list, err := m.List()
		if err != nil {
			return err
		}
		return printJSONOrTable(list, func() {
			if len(list) == 0 {
				fmt.Println("(пусто)")
				return
			}
			for _, c := range list {
				fmt.Printf("%-12s  days=%-4d  until=%s  dns=%s\n",
					c.Name, c.DaysLeft, c.NotAfter.Format("2006-01-02"), strings.Join(c.DNSNames, ","))
			}
		})
	},
}

var certShowCmd = &cobra.Command{
	Use:   "show [name]",
	Short: "Показать детали сертификата (по умолчанию live)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		m, err := openCerts()
		if err != nil {
			return err
		}
		want := "live"
		if len(args) == 1 {
			want = args[0]
		}
		list, err := m.List()
		if err != nil {
			return err
		}
		for _, c := range list {
			if c.Name == want {
				return printJSONOrTable(c, func() {
					fmt.Printf("name:      %s\n", c.Name)
					fmt.Printf("subject:   %s\n", c.Subject)
					fmt.Printf("issuer:    %s\n", c.Issuer)
					fmt.Printf("not_before:%s\n", c.NotBefore)
					fmt.Printf("not_after: %s\n", c.NotAfter)
					fmt.Printf("days_left: %d\n", c.DaysLeft)
					fmt.Printf("dns:       %s\n", strings.Join(c.DNSNames, ", "))
					fmt.Printf("cert:      %s\n", c.CertPath)
					fmt.Printf("key:       %s\n", c.KeyPath)
				})
			}
		}
		return fmt.Errorf("сертификат %q не найден", want)
	},
}

var certImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Импортировать пару cert/key PEM в хранилище",
	RunE: func(cmd *cobra.Command, args []string) error {
		if certImportCert == "" || certImportKey == "" {
			return fmt.Errorf("нужны --cert и --key")
		}
		m, err := openCerts()
		if err != nil {
			return err
		}
		name := certImportName
		if name == "" {
			name = "live"
		}
		if err := m.ImportFiles(certImportCert, certImportKey, name); err != nil {
			return err
		}
		fmt.Println("импортировано:", name)
		return nil
	},
}

var certDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Удалить именованный сертификат из хранилища",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		m, err := openCerts()
		if err != nil {
			return err
		}
		if err := m.Delete(args[0]); err != nil {
			return err
		}
		fmt.Println("удалено:", args[0])
		return nil
	},
}

var certSelfSignedCmd = &cobra.Command{
	Use:   "selfsigned",
	Short: "Сгенерировать self-signed сертификат в live/",
	RunE: func(cmd *cobra.Command, args []string) error {
		m, err := openCerts()
		if err != nil {
			return err
		}
		domains := certDomains
		if len(domains) == 0 {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return err
			}
			domains = []string{cfg.Server.SMTP.Hostname}
		}
		certPEM, keyPEM, err := certs.GenerateSelfSigned(domains, 365*24*time.Hour)
		if err != nil {
			return err
		}
		if err := m.Import(certPEM, keyPEM, "live"); err != nil {
			return err
		}
		fmt.Println("self-signed создан для:", strings.Join(domains, ", "))
		return nil
	},
}

var certCACmd = &cobra.Command{
	Use:   "ca",
	Short: "Управление доверенными УЦ",
}

var certCAListCmd = &cobra.Command{
	Use:   "list",
	Short: "Список дополнительных УЦ",
	RunE: func(cmd *cobra.Command, args []string) error {
		m, err := openCerts()
		if err != nil {
			return err
		}
		names, err := m.ListCA()
		if err != nil {
			return err
		}
		return printJSONOrTable(names, func() {
			if len(names) == 0 {
				fmt.Println("(пусто)")
				return
			}
			for _, n := range names {
				fmt.Println(n)
			}
		})
	},
}

var certCAAddCmd = &cobra.Command{
	Use:   "add <pem-file>",
	Short: "Добавить сертификат УЦ в trust store",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		m, err := openCerts()
		if err != nil {
			return err
		}
		if err := m.AddCA(args[0], certCAName); err != nil {
			return err
		}
		fmt.Println("УЦ добавлен")
		return nil
	},
}

var certCARemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Удалить УЦ из хранилища",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		m, err := openCerts()
		if err != nil {
			return err
		}
		if err := m.RemoveCA(args[0]); err != nil {
			return err
		}
		fmt.Println("УЦ удалён:", args[0])
		return nil
	},
}

var certACMECmd = &cobra.Command{
	Use:   "acme",
	Short: "ACME-клиент (Let's Encrypt и совместимые УЦ)",
}

var certACMEStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Статус ACME и текущего сертификата",
	RunE: func(cmd *cobra.Command, args []string) error {
		m, err := openCerts()
		if err != nil {
			return err
		}
		st := m.ACMEStatus()
		return printJSONOrTable(st, func() {
			b, _ := json.MarshalIndent(st, "", "  ")
			fmt.Println(string(b))
		})
	},
}

var certACMEIssueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Выпустить сертификат через ACME (HTTP-01 / TLS-ALPN-01)",
	RunE: func(cmd *cobra.Command, args []string) error {
		m, err := openCerts()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		info, err := m.IssueACME(ctx, certDomains)
		if err != nil {
			return err
		}
		fmt.Printf("выпущен: %s (до %s, dns=%s)\n",
			info.Subject, info.NotAfter.Format(time.RFC3339), strings.Join(info.DNSNames, ","))
		return nil
	},
}

var certACMERenewCmd = &cobra.Command{
	Use:   "renew",
	Short: "Обновить сертификат через ACME",
	RunE: func(cmd *cobra.Command, args []string) error {
		m, err := openCerts()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		info, err := m.RenewACME(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("обновлён: до %s\n", info.NotAfter.Format(time.RFC3339))
		return nil
	},
}

func openCerts() (*certs.Manager, error) {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return nil, err
	}
	return certs.New(cfg, nil)
}

func printJSONOrTable(v any, plain func()) error {
	if jsonOut {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	plain()
	return nil
}

func init() {
	certImportCmd.Flags().StringVar(&certImportCert, "cert", "", "путь к fullchain.pem / cert.pem")
	certImportCmd.Flags().StringVar(&certImportKey, "key", "", "путь к privkey.pem")
	certImportCmd.Flags().StringVar(&certImportName, "name", "live", "имя в хранилище")

	certSelfSignedCmd.Flags().StringSliceVar(&certDomains, "domain", nil, "DNS-имена (SAN)")
	certACMEIssueCmd.Flags().StringSliceVar(&certDomains, "domain", nil, "домены (иначе из конфига)")

	certCAAddCmd.Flags().StringVar(&certCAName, "name", "", "имя файла в ca/")

	certCACmd.AddCommand(certCAListCmd, certCAAddCmd, certCARemoveCmd)
	certACMECmd.AddCommand(certACMEStatusCmd, certACMEIssueCmd, certACMERenewCmd)
	certCmd.AddCommand(certListCmd, certShowCmd, certImportCmd, certDeleteCmd, certSelfSignedCmd, certCACmd, certACMECmd)
}
