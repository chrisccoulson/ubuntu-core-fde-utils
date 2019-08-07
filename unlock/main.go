package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/chrisccoulson/ubuntu-core-fde-utils"
)

var keyPath string

const (
	masterKeyFilePath string = "/run/unlock.tmp"
)

func init() {
	flag.StringVar(&keyPath, "key-path", "", "")
}

func main() {
	flag.Parse()

	if keyPath == "" {
		fmt.Fprintf(os.Stderr, "Cannot unlock device: missing key path\n")
		os.Exit(1)
	}

	args := flag.Args()
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "Cannot unlock device: insufficient arguments\n")
		os.Exit(1)
	}

	devicePath := args[0]
	name := args[1]

	keyFile, err := os.Open(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot unlock device %s: error opening key file: %v\n", devicePath, err)
		os.Exit(1)
	}
	defer keyFile.Close()

	tpm, err := fdeutil.ConnectToDefaultTPM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot acquire TPM context: %v", err)
		os.Exit(1)
	}
	defer tpm.Close()

	key, err := fdeutil.UnsealKeyFromTPM(tpm, keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot unlock device %s: error unsealing key:: %v\n", devicePath, err)
		os.Exit(1)
	}

	masterKeyFile, err := os.OpenFile(masterKeyFilePath, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot unlock device %s: error creating temporary master key file: %v",
			devicePath, err)
		os.Exit(1)
	}
	defer os.Remove(masterKeyFilePath)
	defer masterKeyFile.Close()

	if _, err := masterKeyFile.Write(key); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot unlock device %s: error writing master key to temporary file: %v",
			devicePath, err)
		os.Exit(1)
	}

	cmd := exec.Command("cryptsetup", "--type", "luks2", "--master-key-file", masterKeyFilePath, "open",
		devicePath, name)
	cmd.Env = append(os.Environ(), "LD_PRELOAD=/lib/no-udev.so")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot unock device %s: cryptsetup execution failed: %v\n",
			devicePath, err)
		os.Exit(1)
	}
}
