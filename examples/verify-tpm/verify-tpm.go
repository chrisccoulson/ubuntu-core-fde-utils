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
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/chrisccoulson/ubuntu-core-fde-utils"
)

var ekCert string
var endorsementAuth string

func init() {
	flag.StringVar(&ekCert, "ek-cert-file", "", "")
	flag.StringVar(&endorsementAuth, "endorsement-auth", "", "")
}

func main() {
	flag.Parse()

	var ekCertReader io.Reader
	if ekCert == "" {
		b := new(bytes.Buffer)
		func() {
			tpm, err := fdeutil.ConnectToDefaultTPM()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot connect to TPM to obtain EK certificate: %v\n", err)
				os.Exit(1)
			}
			defer tpm.Close()
			if err := fdeutil.FetchEkCertificate(tpm, b); err != nil {
				fmt.Fprintf(os.Stderr, "Cannot fetch EK certificate: %v\n", err)
				os.Exit(1)
			}
		}()
		ekCertReader = b
	} else {
		f, err := os.Open(ekCert)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open EK certificate file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		ekCertReader = f
	}

	tpm, err := fdeutil.SecureConnectToDefaultTPM(ekCertReader, []byte(endorsementAuth))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot verify that TPM is genuine: %v\n", err)
		os.Exit(1)
	}
	tpm.Close()

	fmt.Println("TPM is genuine!")
}
