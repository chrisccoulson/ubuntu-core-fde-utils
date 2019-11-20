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

var ekCert string

func init() {
	flag.StringVar(&ekCert, "ek-cert-file", "", "")
}

func main() {
	flag.Parse()

	if ekCert == "" {
		fmt.Fprintf(os.Stderr, "No -ek-cert-file\n")
		os.Exit(1)
	}

	f, err := os.Open(ekCert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot open EK certificate file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	if _, err := fdeutil.SecureConnectToDefaultTPM(f); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot verify that TPM is genuine: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("TPM is genuine!")
}
