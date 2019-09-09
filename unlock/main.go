// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/chrisccoulson/ubuntu-core-fde-utils"
)

var keyFile string
var pin string

const (
	masterKeyFilePath string = "/run/unlock.tmp"
)

func init() {
	flag.StringVar(&keyFile, "key-file", "", "")
	flag.StringVar(&pin, "pin", "", "")
}

func main() {
	flag.Parse()

	if keyFile == "" {
		fmt.Fprintf(os.Stderr, "Cannot unlock device: missing -key-file\n")
		os.Exit(1)
	}

	args := flag.Args()
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "Cannot unlock device: insufficient arguments\n")
		os.Exit(1)
	}

	devicePath := args[0]
	name := args[1]

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

	tpm, err := fdeutil.ConnectToDefaultTPM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot acquire TPM context: %v", err)
		os.Exit(1)
	}
	defer tpm.Close()

	key, err := fdeutil.UnsealKeyFromTPM(tpm, in, pin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot unlock device %s: error unsealing key:: %v\n", devicePath, err)
		os.Exit(1)
	}

	masterKeyFile, err := os.OpenFile(masterKeyFilePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot unlock device %s: error creating temporary master key file: %v",
			devicePath, err)
		os.Exit(1)
	}
	defer func() {
		defer os.Remove(masterKeyFilePath)
		defer masterKeyFile.Close()
	}()

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
		fmt.Fprintf(os.Stderr, "Cannot unlock device %s: cryptsetup execution failed: %v\n",
			devicePath, err)
		os.Exit(1)
	}
}
