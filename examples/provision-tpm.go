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

var (
	requestClear bool
)

func init() {
	flag.BoolVar(&requestClear, "request-clear", false, "")
}

func main() {
	flag.Parse()

	args := flag.Args()

	if requestClear {
		if err := fdeutil.RequestTPMClearUsingPPI(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to request clearing the TPM via the PPI: %v\n", err)
			os.Exit(1)
		}
		return
	}

	var lockoutAuth string
	if len(args) > 0 {
		lockoutAuth = args[0]
	}

	tpm, err := fdeutil.ConnectToDefaultTPM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot acquire TPM context: %v", err)
		os.Exit(1)
	}
	defer tpm.Close()

	if err := fdeutil.ProvisionTPM(tpm, []byte(lockoutAuth)); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to provision the TPM: %v\n", err)
		os.Exit(1)
	}
}
