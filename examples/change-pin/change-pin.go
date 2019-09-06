package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/chrisccoulson/ubuntu-core-fde-utils"
)

var keyFile string
var currentPin string

func init() {
	flag.StringVar(&currentPin, "current-pin", "", "")
	flag.StringVar(&keyFile, "key-file", "", "")
}

func main() {
	flag.Parse()

	if keyFile == "" {
		fmt.Fprintf(os.Stderr, "Cannot change PIN: missing -key-file\n")
		os.Exit(1)
	}

	args := flag.Args()
	var pin string
	if len(args) > 0 {
		pin = args[0]
	}

	tpm, err := fdeutil.ConnectToDefaultTPM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot acquire TPM context: %v", err)
		os.Exit(1)
	}
	defer tpm.Close()

	if err := fdeutil.ChangePIN(tpm, keyFile, currentPin, pin); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot change PIN: %v", err)
		os.Exit(1)
	}
}
