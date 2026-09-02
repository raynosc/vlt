package main

import (
	"fmt"
	"os"

	"github.com/raynosc/vlt/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(cli.ExitErr)
	}
}
