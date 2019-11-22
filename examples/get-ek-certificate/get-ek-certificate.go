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

var parentsOnly bool
func init() {
	flag.BoolVar(&parentsOnly, "parents-only", false, "")
}

func main() {
	flag.Parse()

	if len(flag.Args()) != 1 {
		fmt.Fprintf(os.Stderr, "Incorrect usage\n")
		os.Exit(1)
	}

	tpm, err := fdeutil.ConnectToDefaultTPM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot acquire TPM context: %v\n", err)
		os.Exit(1)
	}

	if err := fdeutil.FetchAndSaveEkCertificateChain(tpm, parentsOnly, flag.Args()[0]); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot fetch and save EK certificate and intermediates: %v\n", err)
		os.Exit(1)
	}
}
