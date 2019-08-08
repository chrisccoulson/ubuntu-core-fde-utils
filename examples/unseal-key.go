package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/chrisccoulson/ubuntu-core-fde-utils"
)

var keyFile string
var outFile string
var pin string

func init() {
	flag.StringVar(&keyFile, "key-file", "", "")
	flag.StringVar(&outFile, "out-file", "", "")
	flag.StringVar(&pin, "pin", "", "")
}

func main() {
	flag.Parse()

	if keyFile == "" {
		fmt.Fprintf(os.Stderr, "Missing -key-file\n")
		os.Exit(1)
	}
	if outFile == "" {
		fmt.Fprintf(os.Stderr, "Missing -out-file\n")
		os.Exit(1)
	}

	var in *os.File
	if keyFile == "-" {
		in = os.Stdin
	} else {
		f, err := os.Open(keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open input file: %v\n", err)
			os.Exit(1)
		}
		in = f
		defer in.Close()
	}

	var out *os.File
	if outFile == "-" {
		out = os.Stdout
	} else {
		f, err := os.OpenFile(outFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open output file: %v\n", err)
			os.Exit(1)
		}
		out = f
		defer out.Close()
	}

	tpm, err := fdeutil.ConnectToDefaultTPM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot acquire TPM context: %v", err)
		os.Exit(1)
	}
	defer tpm.Close()

	key, err := fdeutil.UnsealKeyFromTPM(tpm, in, pin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot unseal key: %v\n", err)
		os.Exit(1)
	}

	_, err = out.Write(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot write unsealed key: %v\n", err)
		os.Exit(1)
	}
}
