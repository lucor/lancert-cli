// Command lancert obtains browser-trusted certificates for private IPv4 development targets.
package main

import (
	"fmt"
	"os"

	"go.lucor.dev/lancert-cli/internal/app"
	lancertcli "go.lucor.dev/lancert-cli/internal/cli"
)

func main() {
	if err := lancertcli.Run(os.Args, os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, app.ProductName+":", err)
		os.Exit(1)
	}
}
