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

type recoveryReason uint8

const (
	recoveryReasonUnexpectedError recoveryReason = iota + 1
	recoveryReasonInvalidKeyFile
	recoveryReasonProvisioningError
	recoveryReasonTPMVerificationError
	recoveryReasonTPMLockout
	recoveryReasonPinFail
)

func activate(volume, sourceDevice string, key []byte, options []string) error {
	keyFilePath, err := func() (string, error) {
		f, err := ioutil.TempFile("/run", "ubuntu-core-cryptsetup.XXXXXX")
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
		return xerrors.Errorf("error saving key for systemd-cryptsetup: %w", err)
	}
	defer os.Remove(keyFilePath)

	cmd := exec.Command("/lib/systemd/systemd-cryptsetup", "attach", volume, sourceDevice, keyFilePath, strings.Join(options, ","))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func askPassword(sourceDevice, msg string) (string, error) {
	cmd := exec.Command(
		"systemd-ask-password",
		"--icon", "drive-harddisk",
		"--id", "ubuntu-core-cryptsetup:"+sourceDevice,
		msg)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return "", xerrors.Errorf("cannot run systemd-ask-password: %w", err)
	}
	result, err := out.ReadString('\n')
	if err != nil {
		return "", xerrors.Errorf("cannot read result from systemd-ask-password: %w", err)
	}
	return strings.TrimRight(result, "\n"), nil
}

func activateWithRecoveryKey(volume, sourceDevice string, tries int, activateOptions []string) error {
	var lastErr error
Retry:
	for i := 0; i < tries; i++ {
		recoveryPassphrase, err := askPassword(sourceDevice, "Please enter the recovery key for disk "+sourceDevice+":")
		if err != nil {
			return err
		}

		// The recovery key should be provided as 8 groups of 5 base-10 digits, with each 5 digits being converted to a 2-byte number
		// to make a 16-byte key.
		var key bytes.Buffer
		for len(recoveryPassphrase) > 0 {
			if len(recoveryPassphrase) < 5 {
				// Badly formatted: not enough digits.
				continue Retry
			}
			x, err := strconv.ParseUint(recoveryPassphrase[0:5], 10, 16)
			if err != nil {
				// Badly formatted: the 5 digits are not a base-10 number that fits in to 2-bytes.
				continue Retry
			}
			binary.Write(&key, binary.LittleEndian, uint16(x))
			// Move to the next 5 digits
			recoveryPassphrase = recoveryPassphrase[5:]
			// Permit each set of 5 digits to be separated by '-', but don't allow the recovery key to end or begin with one.
			if len(recoveryPassphrase) > 1 && recoveryPassphrase[0] == '-' {
				recoveryPassphrase = recoveryPassphrase[1:]
			}
		}

		lastErr = nil
		if err := activate(volume, sourceDevice, key.Bytes(), activateOptions); err != nil {
			lastErr = err
			if _, isExitErr := err.(*exec.ExitError); !isExitErr {
				return err
			}
		} else {
			break
		}
	}

	return lastErr
}

func getPIN(sourceDevice, pinFilePath string) (string, error) {
	if pinFilePath == "" {
		return askPassword(sourceDevice, "Please enter the PIN for disk "+sourceDevice+":")
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

func activateWithTPM(volume, sourceDevice, keyFilePath, ekCertFilePath, pinFilePath string, insecure bool, tries int, activateOptions []string) error {
	keyDataObject, err := fdeutil.LoadSealedKeyObject(keyFilePath)
	if err != nil {
		return xerrors.Errorf("cannot load sealed key object file: %w", err)
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
		return xerrors.Errorf("cannot open TPM connection: %w", err)
	}
	defer tpm.Close()

	var key []byte
	reprovisionAttempted := false

	for {
		var err error
		var pin string
		if keyDataObject.AuthMode2F() == fdeutil.AuthModePIN {
			pin, err = getPIN(sourceDevice, pinFilePath)
			if err != nil {
				return xerrors.Errorf("cannot obtain PIN: %w", err)
			}
			pinFilePath = ""
		}

	RetryUnseal:
		key, err = keyDataObject.UnsealFromTPM(tpm, pin, false)
		if err != nil {
			switch err {
			case fdeutil.ErrProvisioning:
				// ErrProvisioning in this context indicates that there isn't a valid persistent SRK. Have a go at creating one now and then
				// retrying the unseal operation - if the previous SRK was evicted, the TPM owner hasn't changed and the storage hierarchy still
				// has a null authorization value, then this will allow us to unseal the key without requiring any type of manual recovery. If the
				// storage hierarchy has a non-null authorization value, ProvionTPM will fail. If the TPM owner has changed, ProvisionTPM might
				// succeed, but UnsealFromTPM will fail with InvalidKeyFileError when retried.
				if !reprovisionAttempted {
					reprovisionAttempted = true
					fmt.Fprintf(os.Stderr, "TPM is not provisioned correctly - attempting automatic recovery...\n")
					if err := fdeutil.ProvisionTPM(tpm, fdeutil.ProvisionModeWithoutLockout, nil, nil); err == nil {
						fmt.Fprintf(os.Stderr, " ...automatic recovery succeeded. Retrying key unseal operation now\n")
						goto RetryUnseal
					} else {
						fmt.Fprintf(os.Stderr, " ...automatic recovery failed: %v\n", err)
					}
				}
			case fdeutil.ErrPinFail:
				tries -= 1
				if tries > 0 {
					continue
				}
			}
			return xerrors.Errorf("cannot unseal intermediate key from TPM: %w", err)
		}
		break
	}

	return activate(volume, sourceDevice, key, activateOptions)
}

func run() int {
	args := flag.Args()
	if len(args) == 0 {
		fmt.Printf("Usage: ubuntu-core-cryptsetup VOLUME SOURCE-DEVICE KEY-FILE EK-CERT-FILE [PIN] [OPTIONS]\n")
		return 0
	}

	if len(args) < 4 {
		fmt.Fprintf(os.Stderr, "Cannot activate device: insufficient arguments\n")
		return 1
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
	pinTries := 1
	recoveryTries := 1
	var filteredOptions []string

	if len(args) >= 6 && args[5] != "" && args[5] != "-" && args[5] != "none" {
		opts := strings.Split(args[5], ",")
		for _, opt := range opts {
			switch {
			case opt == "insecure-tpm-connection":
				insecure = true
			case strings.HasPrefix(opt, "tries="):
				// Filter out "tries="
				// systemd-cryptsetup is always called with "tries=1", and we'll loop on the PIN until TPM lockout
			case strings.HasPrefix(opt, "pin-tries="):
				u, err := strconv.ParseUint(strings.TrimPrefix(opt, "pin-tries="), 10, 8)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Cannot activate device %s: invalid value for \"recovery-tries=\"\n", sourceDevice)
					return 1
				}
				pinTries = int(u)
			case strings.HasPrefix(opt, "recovery-tries="):
				u, err := strconv.ParseUint(strings.TrimPrefix(opt, "recovery-tries="), 10, 8)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Cannot activate device %s: invalid value for \"recovery-tries=\"\n", sourceDevice)
					return 1
				}
				recoveryTries = int(u)
			default:
				filteredOptions = append(filteredOptions, opt)
			}
		}
	}

	recoveryReasonFilePath := "/run/ucc-recovery-reason." + volume
	filteredOptions = append(filteredOptions, "tries=1")

	if err := activateWithTPM(volume, sourceDevice, keyFilePath, ekCertFilePath, pinFilePath, insecure, pinTries, filteredOptions); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot activate device %s with TPM: %v\n", sourceDevice, err)

		var ikfe fdeutil.InvalidKeyFileError
		var ecve fdeutil.EkCertVerificationError
		var tpmve fdeutil.TPMVerificationError
		var pe *os.PathError

		recoveryReason := recoveryReasonUnexpectedError

		switch {
		case xerrors.As(err, &ikfe):
			recoveryReason = recoveryReasonInvalidKeyFile
		case xerrors.Is(err, fdeutil.ErrProvisioning):
			recoveryReason = recoveryReasonProvisioningError
		case xerrors.As(err, &ecve):
			recoveryReason = recoveryReasonTPMVerificationError
		case xerrors.As(err, &tpmve):
			recoveryReason = recoveryReasonTPMVerificationError
		case xerrors.As(err, &pe) && pe.Path == ekCertFilePath:
			recoveryReason = recoveryReasonTPMVerificationError
		case xerrors.Is(err, fdeutil.ErrLockout):
			recoveryReason = recoveryReasonTPMLockout
		case xerrors.Is(err, fdeutil.ErrPinFail):
			recoveryReason = recoveryReasonPinFail
		}

		if err := activateWithRecoveryKey(volume, sourceDevice, recoveryTries, filteredOptions); err != nil {
			fmt.Fprintf(os.Stderr, "Cannot activate device %s with recovery key: %v\n", sourceDevice, err)
			return 1
		}

		f, err := os.OpenFile(recoveryReasonFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err == nil {
			defer f.Close()
			f.Write([]byte{byte(recoveryReason)})
		}

		fmt.Printf("Successfully activated device %s with recovery key (reason %d)\n", sourceDevice, recoveryReason)
		return 0
	}

	os.Remove(recoveryReasonFilePath)
	fmt.Printf("Successfully activated device %s with TPM\n", sourceDevice)
	return 0
}

func main() {
	flag.Parse()
	os.Exit(run())
}
