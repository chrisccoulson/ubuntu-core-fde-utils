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

	"golang.org/x/xerrors"
)

var insecure bool

var ekCertFile string
var keyFile string
var pin string

const (
	masterKeyFilePath string = "/run/unlock.tmp"
)

const (
	unspecifiedErrorExitCode = iota + 1
	invalidArgsExitCode
	invalidKeyFileExitCode
	ekCertVerificationErrExitCode
	tpmVerificationErrExitCode
	tpmProvisioningErrExitCode
	tpmLockedOutExitCode
	pinFailExitCode
)

func init() {
	flag.BoolVar(&insecure, "insecure", false, "")
	flag.StringVar(&ekCertFile, "ek-cert-file", "", "")
	flag.StringVar(&keyFile, "key-file", "", "")
	flag.StringVar(&pin, "pin", "", "")
}

func run() int {
	if ekCertFile == "" && !insecure {
		fmt.Fprintf(os.Stderr, "Cannot unlock device: missing -ek-cert-file\n")
		return invalidArgsExitCode
	}

	if keyFile == "" {
		fmt.Fprintf(os.Stderr, "Cannot unlock device: missing -key-file\n")
		return invalidArgsExitCode
	}

	args := flag.Args()
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "Cannot unlock device: insufficient arguments\n")
		return invalidArgsExitCode
	}

	devicePath := args[0]
	name := args[1]

	var in *os.File
	if keyFile == "-" {
		in = os.Stdin
	} else {
		f, err := os.Open(keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot unlock device %s: cannot open key file: %v\n", devicePath, err)
			return invalidKeyFileExitCode
		}
		in = f
		defer in.Close()
	}

	tpm, err := func() (*fdeutil.TPMConnection, error) {
		if !insecure {
			ekCertReader, err := os.Open(ekCertFile)
			if err != nil {
				return nil, xerrors.Errorf("cannot open endorsement key certificate file: %w", err)
			}
			defer ekCertReader.Close()
			return fdeutil.SecureConnectToDefaultTPM(ekCertReader, nil)
		}
		return fdeutil.ConnectToDefaultTPM()
	}()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot open TPM connection: %v", err)
		ret := unspecifiedErrorExitCode
		switch err {
		case fdeutil.ErrProvisioning:
			// ErrProvisioning indicates that there isn't a valid persistent EK, and a transient one can't be created because the endorsement
			// hierarchy has a non-null authorization value. There's no point in trying ProvisionTPM to create a persistent one here, because
			// we know that will fail too without the endorsement hierarchy authorization - the only way to recover at this point is to call
			// ProvisionTPM with the correct endorsement hierarchy authorization value, or with mode == ProvisionModeClear.
			ret = tpmProvisioningErrExitCode
		default:
			var pe *os.PathError
			if _, ok := err.(fdeutil.EkCertVerificationError); ok {
				ret = ekCertVerificationErrExitCode
			} else if _, ok := err.(fdeutil.TPMVerificationError); ok {
				ret = tpmVerificationErrExitCode
			} else if xerrors.As(err, &pe) && pe.Path == ekCertFile {
				ret = ekCertVerificationErrExitCode
			}
		}
		return ret
	}
	defer tpm.Close()

	reprovisionAttempted := false

RetryUnseal:
	key, err := fdeutil.UnsealKeyFromTPM(tpm, in, pin, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot unlock device %s: error unsealing key: %v\n", devicePath, err)
		ret := unspecifiedErrorExitCode
		switch err {
		case fdeutil.ErrProvisioning:
			// ErrProvisioning in this context indicates that there isn't a valid persistent SRK. Have a go at creating one now and then
			// retrying the unseal operation - if the previous SRK was evicted, the TPM owner hasn't changed and the storage hierarchy still
			// has a null authorization value, then this will allow us to unseal the key without requiring any type of manual recovery. If the
			// storage hierarchy has a non-null authorization value, ProvionTPM will fail. If the TPM owner has changed, ProvisionTPM might
			// succeed, but UnsealKeyFromTPM will fail with InvalidKeyFileError when retried.
			if !reprovisionAttempted {
				reprovisionAttempted = true
				fmt.Fprintf(os.Stderr, " Attempting automatic recovery...\n")
				if err := fdeutil.ProvisionTPM(tpm, fdeutil.ProvisionModeWithoutLockout, nil, nil); err == nil {
					fmt.Fprintf(os.Stderr, " ...ProvisionTPM succeeded. Retrying unseal operation now\n")
					goto RetryUnseal
				} else {
					fmt.Fprintf(os.Stderr, " ...ProvisionTPM failed: %v\n", err)
				}
			}
			ret = tpmProvisioningErrExitCode
		case fdeutil.ErrLockout:
			ret = tpmLockedOutExitCode
		case fdeutil.ErrPinFail:
			ret = pinFailExitCode
		default:
			if _, ok := err.(fdeutil.InvalidKeyFileError); ok {
				ret = invalidKeyFileExitCode
			}
		}
		return ret
	}

	masterKeyFile, err := os.OpenFile(masterKeyFilePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot unlock device %s: error creating temporary master key file: %v", devicePath, err)
		return unspecifiedErrorExitCode
	}
	defer func() {
		defer os.Remove(masterKeyFilePath)
		defer masterKeyFile.Close()
	}()

	if _, err := masterKeyFile.Write(key); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot unlock device %s: error writing master key to temporary file: %v", devicePath, err)
		return unspecifiedErrorExitCode
	}

	cmd := exec.Command("cryptsetup", "--type", "luks2", "--master-key-file", masterKeyFilePath, "open", devicePath, name)
	cmd.Env = append(os.Environ(), "LD_PRELOAD=/lib/no-udev.so")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot unlock device %s: cryptsetup execution failed: %v\n", devicePath, err)
		return unspecifiedErrorExitCode
	}

	return 0
}

func main() {
	flag.Parse()
	os.Exit(run())
}
