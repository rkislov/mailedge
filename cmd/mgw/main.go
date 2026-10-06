package main

import (
	"os"

	"github.com/rkislov/mailedge/cmd/mgw/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
