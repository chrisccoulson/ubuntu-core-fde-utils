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

func run() int {
	if keyFile == "" {
		fmt.Fprintf(os.Stderr, "Missing -key-file\n")
		return 1
	}
	if outFile == "" {
		fmt.Fprintf(os.Stderr, "Missing -out-file\n")
		return 1
	}

	var in *os.File
	if keyFile == "-" {
		in = os.Stdin
	} else {
		f, err := os.Open(keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open input file: %v\n", err)
			return 1
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
			return 1
		}
		out = f
		defer out.Close()
	}

	tpm, err := fdeutil.ConnectToDefaultTPM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot acquire TPM context: %v", err)
		return 1
	}
	defer tpm.Close()

	key, err := fdeutil.UnsealKeyFromTPM(tpm, in, pin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot unseal key: %v\n", err)
		return 1
	}

	_, err = out.Write(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot write unsealed key: %v\n", err)
		return 1
	}

	return 0
}

func main() {
	flag.Parse()
	os.Exit(run())
}
