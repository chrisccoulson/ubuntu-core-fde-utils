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
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/chrisccoulson/go-tpm2"
	"github.com/chrisccoulson/ubuntu-core-fde-utils"
)

type pathList []string

func (l *pathList) String() string {
	var builder bytes.Buffer
	for i, path := range *l {
		if i > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString(path)
	}
	return builder.String()
}

func (l *pathList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

var update bool
var masterKeyFile string
var keyFile string
var pinIndex string
var policyRevocationIndex string
var ownerAuth string
var kernels pathList
var grubs pathList
var shims pathList

func init() {
	flag.BoolVar(&update, "update", false, "")
	flag.StringVar(&masterKeyFile, "master-key-file", "", "")
	flag.StringVar(&keyFile, "key-file", "", "")
	flag.StringVar(&pinIndex, "pin-index", "", "")
	flag.StringVar(&policyRevocationIndex, "policy-revocation-index", "", "")
	flag.StringVar(&ownerAuth, "auth", "", "")
	flag.Var(&kernels, "with-kernel", "")
	flag.Var(&grubs, "with-grub", "")
	flag.Var(&shims, "with-shim", "")
}

func run() int {
	if masterKeyFile == "" {
		fmt.Fprintf(os.Stderr, "Missing -master-key-file\n")
		return 1
	}
	if keyFile == "" {
		fmt.Fprintf(os.Stderr, "Missing -key-file\n")
		return 1
	}

	var in *os.File
	if masterKeyFile == "-" {
		in = os.Stdin
	} else {
		f, err := os.Open(masterKeyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open key file: %v\n", err)
			return 1
		}
		in = f
		defer in.Close()
	}

	var pinHandle tpm2.Handle
	if pinIndex != "" {
		if h, err := hex.DecodeString(pinIndex); err != nil {
			fmt.Fprintf(os.Stderr, "Invalid -pin-index: %v\n", err)
			return 1
		} else {
			pinHandle = tpm2.Handle(binary.BigEndian.Uint32(h))
		}
	}
	var policyRevokeHandle tpm2.Handle
	if policyRevocationIndex != "" {
		if h, err := hex.DecodeString(policyRevocationIndex); err != nil {
			fmt.Fprintf(os.Stderr, "Invalid -policy-revocation-index: %v\n", err)
			return 1
		} else {
			policyRevokeHandle = tpm2.Handle(binary.BigEndian.Uint32(h))
		}
	}

	key, err := ioutil.ReadAll(in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read key: %v\n", err)
		return 1
	}

	var create *fdeutil.CreationParams
	if !update {
		create = &fdeutil.CreationParams{PolicyRevocationHandle: policyRevokeHandle, PinHandle: pinHandle, OwnerAuth: []byte(ownerAuth)}
	}

	tpm, err := fdeutil.ConnectToDefaultTPM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot acquire TPM context: %v", err)
		return 1
	}
	defer tpm.Close()

	var params *fdeutil.SealParams
	if len(shims) > 0 || len(grubs) > 0 || len(kernels) > 0 {
		params = &fdeutil.SealParams{}
	}

	for _, shim := range shims {
		s := &fdeutil.OSComponent{LoadType: fdeutil.FirmwareLoad, Image: fdeutil.FileOSComponent(shim)}
		for _, grub := range grubs {
			g := &fdeutil.OSComponent{LoadType: fdeutil.DirectLoadWithShimVerify,
				Image: fdeutil.FileOSComponent(grub)}
			for _, kernel := range kernels {
				k := &fdeutil.OSComponent{LoadType: fdeutil.DirectLoadWithShimVerify,
					Image: fdeutil.FileOSComponent(kernel)}
				g.Next = append(g.Next, k)
			}
			s.Next = append(s.Next, g)
		}
		params.LoadPaths = append(params.LoadPaths, s)
	}

	if err := fdeutil.SealKeyToTPM(tpm, keyFile, create, params, key); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot seal key to TPM: %v\n", err)
		return 1
	}

	return 0
}

func main() {
	flag.Parse()
	os.Exit(run())
}
