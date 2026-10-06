package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rkislov/mailedge/internal/config"
	"github.com/rkislov/mailedge/internal/filter"
	"github.com/rkislov/mailedge/internal/mailmsg"
	mimeutil "github.com/rkislov/mailedge/internal/mime"
	"github.com/rkislov/mailedge/internal/policy"
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Диагностика фильтров и политик",
}

var testMailCmd = &cobra.Command{
	Use:   "mail <file.eml>",
	Short: "Прогнать EML через policy + filters (dry-run)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		from, _ := cmd.Flags().GetString("from")
		to, _ := cmd.Flags().GetString("to")
		ip, _ := cmd.Flags().GetString("ip")
		helo, _ := cmd.Flags().GetString("helo")

		parsed, _ := mimeutil.Parse(raw)
		msg := &mailmsg.Message{
			From:     from,
			To:       splitCSVFlag(to),
			RemoteIP: ip,
			Helo:     helo,
			Size:     int64(len(raw)),
		}
		if parsed != nil {
			msg.Subject = parsed.Subject
			if msg.From == "" && parsed.From != "" {
				msg.From = parsed.From
			}
		}
		if msg.RemoteIP == "" {
			msg.RemoteIP = "127.0.0.1"
		}

		eng := policy.New(cfg)
		polRes, err := eng.Evaluate(context.Background(), msg, raw)
		if err != nil {
			return err
		}
		chain, err := filter.BuildChain(cfg, nil)
		if err != nil {
			return err
		}
		fres, err := chain.Process(context.Background(), msg, raw)
		if err != nil {
			return err
		}

		final := mergeDryRun(polRes, fres)
		out := map[string]any{
			"file":     filepath.Base(args[0]),
			"from":     msg.From,
			"to":       msg.To,
			"subject":  msg.Subject,
			"remote_ip": msg.RemoteIP,
			"policy":   polRes,
			"filters":  fres,
			"verdict":  final,
		}
		if jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(out)
		}
		fmt.Printf("file: %s\nfrom: %s\nto: %s\nsubject: %s\nip: %s\n", args[0], msg.From, strings.Join(msg.To, ", "), msg.Subject, msg.RemoteIP)
		fmt.Printf("policy:  action=%s reason=%s\n", polRes.Action, polRes.Reason)
		fmt.Printf("filters: action=%s score=%.1f reason=%s tags=%v\n", fres.Action, fres.Score, fres.Reason, fres.Tags)
		fmt.Printf("verdict: %s\n", final.Action)
		if final.Reason != "" {
			fmt.Printf("reason:  %s\n", final.Reason)
		}
		return nil
	},
}

func mergeDryRun(pol, fil *mailmsg.Result) *mailmsg.Result {
	if pol != nil {
		switch strings.ToLower(pol.Action) {
		case "reject", "discard", "quarantine", "hold":
			return pol
		}
	}
	if fil != nil {
		return fil
	}
	return &mailmsg.Result{Action: "accept"}
}

func splitCSVFlag(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func init() {
	testMailCmd.Flags().String("from", "", "envelope from")
	testMailCmd.Flags().String("to", "", "envelope to (CSV)")
	testMailCmd.Flags().String("ip", "", "remote IP")
	testMailCmd.Flags().String("helo", "", "HELO/EHLO")
	testCmd.AddCommand(testMailCmd)
	rootCmd.AddCommand(testCmd)
}
