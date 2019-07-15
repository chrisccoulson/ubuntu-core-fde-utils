package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/chrisccoulson/ubuntu-core-fde-utils"
)

var sealedKeyPath string
var outPath string

func init() {
	flag.StringVar(&sealedKeyPath, "sealed-key-path", "", "")
	flag.StringVar(&outPath, "out-path", "", "")
}

func main() {
	flag.Parse()

	if sealedKeyPath == "" {
		fmt.Fprintf(os.Stderr, "Missing sealed-key-path\n")
		os.Exit(1)
	}
	if outPath == "" {
		fmt.Fprintf(os.Stderr, "Missing out-path\n")
		os.Exit(1)
	}

	var in *os.File
	if sealedKeyPath == "-" {
		in = os.Stdin
	} else {
		f, err := os.Open(sealedKeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open sealed key file: %v\n", err)
			os.Exit(1)
		}
		in = f
		defer in.Close()
	}

	var out *os.File
	if outPath == "-" {
		out = os.Stdout
	} else {
		f, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open output file: %v\n", err)
			os.Exit(1)
		}
		out = f
		defer out.Close()
	}

	key, err := fdeutil.UnsealKeyFromTPM(in)
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
