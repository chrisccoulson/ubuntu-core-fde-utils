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
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/chrisccoulson/ubuntu-core-fde-utils"

	"golang.org/x/xerrors"
)

const (
	unsealedKeyFileNameTemplate = "ubuntu-core-cryptsetup.XXXXXX"
)

const (
	unexpectedErrorExitCode = iota + 1
	invalidArgsExitCode
	invalidKeyFileExitCode
	ekCertVerificationErrExitCode
	tpmVerificationErrExitCode
	tpmProvisioningErrExitCode
	tpmLockedOutExitCode
	pinFailExitCode
	activationFailExitCode
)

func getPIN(sourceDevice, pinFilePath string) (string, error) {
	if pinFilePath == "" {
		cmd := exec.Command(
			"systemd-ask-password",
			"--icon", "drive-harddisk",
			"--id", "ubuntu-core-cryptsetup:"+sourceDevice,
			"Please enter the PIN for disk "+sourceDevice+":")
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stdin = os.Stdin
		if err := cmd.Run(); err != nil {
			return "", xerrors.Errorf("cannot run systemd-ask-password: %w", err)
		}
		pin, err := out.ReadString('\n')
		fmt.Println(pin)
		if err != nil {
			return "", xerrors.Errorf("cannot read PIN from stdout: %w", err)
		}
		return strings.TrimRight(pin, "\n"), nil
	}

	file, err := os.Open(pinFilePath)
	if err != nil {
		return "", xerrors.Errorf("cannot open PIN file: %w", err)
	}
	defer file.Close()

	pin, err := ioutil.ReadAll(file)
	if err != nil {
		return "", xerrors.Errorf("cannot read PIN file contents: %w", err)
	}
	return string(pin), nil
}

func run() int {
	args := flag.Args()
	if len(args) == 0 {
		fmt.Printf("Usage: ubuntu-core-cryptsetup VOLUME SOURCE-DEVICE KEY-FILE EK-CERT-FILE [PIN] [OPTIONS]\n")
		return 0
	}

	if len(args) < 4 {
		fmt.Fprintf(os.Stderr, "Cannot activate device: insufficient arguments\n")
		return invalidArgsExitCode
	}

	volume := args[0]
	sourceDevice := args[1]
	keyFilePath := args[2]

	var ekCertFilePath string
	if args[3] != "" && args[3] != "-" && args[3] != "none" {
		ekCertFilePath = args[3]
	}

	var pinFilePath string
	if len(args) >= 5 && args[4] != "" && args[4] != "-" && args[4] != "none" {
		pinFilePath = args[4]
	}

	var insecure bool
	tries := 1
	var filteredOptions []string

	if len(args) >= 6 && args[5] != "" && args[5] != "-" && args[5] != "none" {
		opts := strings.Split(args[5], ",")
		for _, opt := range opts {
			switch {
			case opt == "insecure-tpm-connection":
				insecure = true
			case strings.HasPrefix(opt, "tries="):
				var err error
				tries, err = strconv.Atoi(strings.TrimPrefix(opt, "tries="))
				if err != nil || tries < 1 {
					fmt.Fprintf(os.Stderr, "Cannot activate device %s: invalid value for \"tries=\"\n", sourceDevice)
					return invalidArgsExitCode
				}
			default:
				filteredOptions = append(filteredOptions, opt)
			}
		}
	}

	keyDataObject, err := fdeutil.LoadSealedKeyObject(keyFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot activate device %s: cannot load sealed key object file: %v\n", sourceDevice, err)
		return invalidKeyFileExitCode
	}

	tpm, err := func() (*fdeutil.TPMConnection, error) {
		if !insecure {
			ekCertReader, err := os.Open(ekCertFilePath)
			if err != nil {
				return nil, xerrors.Errorf("cannot open endorsement key certificate file: %w", err)
			}
			defer ekCertReader.Close()
			return fdeutil.SecureConnectToDefaultTPM(ekCertReader, nil)
		}
		return fdeutil.ConnectToDefaultTPM()
	}()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot activate device %s: error opening TPM connection: %v\n", sourceDevice, err)
		ret := unexpectedErrorExitCode
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
			} else if xerrors.As(err, &pe) && pe.Path == ekCertFilePath {
				ret = ekCertVerificationErrExitCode
			}
		}
		return ret
	}
	defer tpm.Close()

	reprovisionAttempted := false
	var key []byte

	for {
		var err error
		var pin string
		if keyDataObject.AuthMode2F() == fdeutil.AuthModePIN {
			pin, err = getPIN(sourceDevice, pinFilePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot activate device %s: cannot obtain PIN: %v\n", sourceDevice, err)
				return unexpectedErrorExitCode
			}
			pinFilePath = ""
		}

	RetryUnseal:
		key, err = keyDataObject.UnsealFromTPM(tpm, pin, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot activate device %s: error unsealing key: %v\n", sourceDevice, err)
			ret := unexpectedErrorExitCode
			switch err {
			case fdeutil.ErrProvisioning:
				// ErrProvisioning in this context indicates that there isn't a valid persistent SRK. Have a go at creating one now and then
				// retrying the unseal operation - if the previous SRK was evicted, the TPM owner hasn't changed and the storage hierarchy still
				// has a null authorization value, then this will allow us to unseal the key without requiring any type of manual recovery. If the
				// storage hierarchy has a non-null authorization value, ProvionTPM will fail. If the TPM owner has changed, ProvisionTPM might
				// succeed, but UnsealFromTPM will fail with InvalidKeyFileError when retried.
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
				tries -= 1
				if tries > 0 {
					continue
				}
				ret = pinFailExitCode
			default:
				if _, ok := err.(fdeutil.InvalidKeyFileError); ok {
					ret = invalidKeyFileExitCode
				}
			}
			return ret
		}
		break
	}

	unsealedKeyFilePath, err := func() (string, error) {
		f, err := ioutil.TempFile("/run", unsealedKeyFileNameTemplate)
		if err != nil {
			return "", xerrors.Errorf("cannot create temporary file: %w", err)
		}
		defer f.Close()
		if err := f.Chmod(0600); err != nil {
			return "", err
		}
		if _, err := f.Write(key); err != nil {
			return "", xerrors.Errorf("cannot write key to file: %w", err)
		}
		return f.Name(), nil
	}()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot activate device %s: error saving unsealed key to temporary file: %v\n", sourceDevice, err)
		return unexpectedErrorExitCode
	}
	defer os.Remove(unsealedKeyFilePath)

	filteredOptions = append(filteredOptions, "tries=1")

	cmd := exec.Command("/lib/systemd/systemd-cryptsetup", "attach", volume, sourceDevice, unsealedKeyFilePath, strings.Join(filteredOptions, ","))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		ret := unexpectedErrorExitCode
		switch e := err.(type) {
		case *exec.ExitError:
			_ = e
			ret = activationFailExitCode
		}
		fmt.Fprintf(os.Stderr, "Cannot activate device %s: %v\n", sourceDevice, err)
		return ret
	}

	return 0
}

func main() {
	flag.Parse()
	os.Exit(run())
}
