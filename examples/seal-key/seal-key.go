package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/chrisccoulson/ubuntu-core-fde-utils"
)

var update bool
var masterKeyFile string
var keyFile string

func init() {
	flag.BoolVar(&update, "update", false, "")
	flag.StringVar(&masterKeyFile, "master-key-file", "", "")
	flag.StringVar(&keyFile, "key-file", "", "")
}

func main() {
	flag.Parse()

	if masterKeyFile == "" {
		fmt.Fprintf(os.Stderr, "Missing -master-key-file\n")
		os.Exit(1)
	}
	if keyFile == "" {
		fmt.Fprintf(os.Stderr, "Missing -key-file\n")
		os.Exit(1)
	}

	var in *os.File
	if masterKeyFile == "-" {
		in = os.Stdin
	} else {
		f, err := os.Open(masterKeyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open key file: %v\n", err)
			os.Exit(1)
		}
		in = f
		defer in.Close()
	}

	key, err := ioutil.ReadAll(in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read key: %v\n", err)
		os.Exit(1)
	}

	mode := fdeutil.Create
	if update {
		mode = fdeutil.Update
	}

	tpm, err := fdeutil.ConnectToDefaultTPM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot acquire TPM context: %v", err)
		os.Exit(1)
	}
	defer tpm.Close()

	if err := fdeutil.SealKeyToTPM(tpm, keyFile, mode, key); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot seal key to TPM: %v\n", err)
		os.Exit(1)
	}
}
