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
