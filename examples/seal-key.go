package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/chrisccoulson/ubuntu-core-fde-utils"
)

var clearKeyPath string
var outPath string

func init() {
	flag.StringVar(&clearKeyPath, "clear-key-path", "", "")
	flag.StringVar(&outPath, "out-path", "", "")
}

func main() {
	flag.Parse()

	if clearKeyPath == "" {
		fmt.Fprintf(os.Stderr, "Missing clear-key-path\n")
		os.Exit(1)
	}
	if outPath == "" {
		fmt.Fprintf(os.Stderr, "Missing out-path\n")
		os.Exit(1)
	}

	var in *os.File
	if clearKeyPath == "-" {
		in = os.Stdin
	} else {
		in, err := os.Open(clearKeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open key file: %v\n", err)
			os.Exit(1)
		}
		defer in.Close()
	}

	key, err := ioutil.ReadAll(in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read key: %v\n", err)
		os.Exit(1)
	}

	var out *os.File
	if outPath == "-" {
		out = os.Stdout
	} else {
		out, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open output file: %v\n", err)
			os.Exit(1)
		}
		defer out.Close()
	}

	if err := fdeutil.SealKeyToTPM(out, key); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot seal key to TPM: %v\n", err)
		os.Exit(1)
	}
}
