package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/rkislov/mailedge/internal/config"
	"github.com/rkislov/mailedge/internal/intel"
	"github.com/rkislov/mailedge/internal/storage/sqlite"
)

var iocCmd = &cobra.Command{
	Use:   "ioc",
	Short: "Threat Intel — IOC CRUD / feeds",
}

func openIOCStore() (*intel.Store, *sqlite.DB, error) {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return nil, nil, err
	}
	path := cfg.Storage.SQLite.Path
	if path == "" {
		path = cfg.Storage.DataDir + "/mgw.db"
	}
	db, err := sqlite.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return intel.NewStore(db.SQL()), db, nil
}

var iocListCmd = &cobra.Command{
	Use:   "list",
	Short: "Список IOC",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, db, err := openIOCStore()
		if err != nil {
			return err
		}
		defer db.Close()
		typ, _ := cmd.Flags().GetString("type")
		src, _ := cmd.Flags().GetString("source")
		q, _ := cmd.Flags().GetString("q")
		limit, _ := cmd.Flags().GetInt("limit")
		list, err := store.List(context.Background(), typ, src, q, limit)
		if err != nil {
			return err
		}
		if jsonOut {
			return json.NewEncoder(os.Stdout).Encode(list)
		}
		for _, i := range list {
			fmt.Printf("%d\t%s\t%s\t%s\t%s\t%v\n", i.ID, i.Type, i.Value, i.Threat, i.Source, i.Enabled)
		}
		return nil
	},
}

var iocAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Добавить IOC",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, db, err := openIOCStore()
		if err != nil {
			return err
		}
		defer db.Close()
		typ, _ := cmd.Flags().GetString("type")
		val, _ := cmd.Flags().GetString("value")
		threat, _ := cmd.Flags().GetString("threat")
		action, _ := cmd.Flags().GetString("action")
		id, err := store.Upsert(context.Background(), intel.IOC{
			Type: typ, Value: val, Threat: threat, Action: action, Source: "manual",
		})
		if err != nil {
			return err
		}
		fmt.Println(id)
		return nil
	},
}

var iocDelCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Удалить IOC",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		store, db, err := openIOCStore()
		if err != nil {
			return err
		}
		defer db.Close()
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return err
		}
		return store.Delete(context.Background(), id)
	},
}

var iocLookupCmd = &cobra.Command{
	Use:   "lookup <type> <value>",
	Short: "Проверить IOC",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		store, db, err := openIOCStore()
		if err != nil {
			return err
		}
		defer db.Close()
		hit, err := store.Get(context.Background(), args[0], args[1])
		if err != nil {
			return err
		}
		if hit == nil {
			fmt.Println("not found")
			return nil
		}
		if jsonOut {
			return json.NewEncoder(os.Stdout).Encode(hit)
		}
		fmt.Printf("%s %s threat=%s source=%s action=%s\n", hit.Type, hit.Value, hit.Threat, hit.Source, hit.Action)
		return nil
	},
}

var iocImportCmd = &cobra.Command{
	Use:   "import <file.json>",
	Short: "Импорт JSON-массива IOC",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		store, db, err := openIOCStore()
		if err != nil {
			return err
		}
		defer db.Close()
		f, err := os.Open(args[0])
		if err != nil {
			return err
		}
		defer f.Close()
		n, err := store.ImportJSON(context.Background(), f)
		if err != nil {
			return err
		}
		fmt.Printf("imported %d\n", n)
		return nil
	},
}

var iocExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Экспорт IOC в JSON",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, db, err := openIOCStore()
		if err != nil {
			return err
		}
		defer db.Close()
		return store.ExportJSON(context.Background(), os.Stdout)
	},
}

var iocRefreshCmd = &cobra.Command{
	Use:   "refresh",
	Short: "Обновить ThreatFox / qfeed",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		store, db, err := openIOCStore()
		if err != nil {
			return err
		}
		defer db.Close()
		feeder := intel.NewFeeder(store, func() config.IntelConfig { return cfg.Filters.Intel }, nil)
		n, err := feeder.Refresh(context.Background())
		if err != nil {
			return err
		}
		fmt.Printf("upserted %d\n", n)
		return nil
	},
}

func init() {
	iocListCmd.Flags().String("type", "", "filter by type")
	iocListCmd.Flags().String("source", "", "filter by source")
	iocListCmd.Flags().String("q", "", "search")
	iocListCmd.Flags().Int("limit", 100, "limit")
	iocAddCmd.Flags().String("type", "ip", "ip|domain|url|hash")
	iocAddCmd.Flags().String("value", "", "IOC value")
	iocAddCmd.Flags().String("threat", "", "threat label")
	iocAddCmd.Flags().String("action", "", "optional action override")
	_ = iocAddCmd.MarkFlagRequired("value")

	iocCmd.AddCommand(iocListCmd, iocAddCmd, iocDelCmd, iocLookupCmd, iocImportCmd, iocExportCmd, iocRefreshCmd)
	rootCmd.AddCommand(iocCmd)
}
