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

package fdeutil

import (
	"errors"
	"fmt"

	"github.com/chrisccoulson/go-tpm2"
)

var (
	ErrClearRequiresPPI    = errors.New("clearing requires the use of the Physical Presence Interface")
	ErrRequiresLockoutAuth = errors.New("the TPM indicates the lockout hierarchy has an authorization value, but one hasn't " +
		"been provided")

	ErrProvisioning  = errors.New("the TPM is not correctly provisioned")
	ErrKeyFileExists = errors.New("a key data file already exists at the specified path")

	// ErrLockout is returned from any function when the TPM is in dictionary-attack lockout mode. Until
	// the TPM exits lockout mode, the key will need to be recovered via a mechanism that is independent of
	// the TPM (eg, a recovery key)
	ErrLockout = errors.New("the TPM is in DA lockout mode")

	// ErrPinFail is returned from UnsealKeyFromTPM if the provided PIN is incorrect.
	ErrPinFail = errors.New("the provided PIN is incorrect")
)

type TPMResourceExistsError struct {
	Handle tpm2.Handle
}

func (e TPMResourceExistsError) Error() string {
	return fmt.Sprintf("a resource already exists on the TPM at handle 0x%08x", e.Handle)
}

type InvalidKeyFileError struct {
	msg string
}

func (e InvalidKeyFileError) Error() string {
	return fmt.Sprintf("invalid key data file: %s", e.msg)
}

// AuthFailError is returned when an authorization fails.
type AuthFailError struct {
	Handle tpm2.Handle
}

func (e AuthFailError) Error() string {
	return fmt.Sprintf("an authorization check failed for the hierarchy associated with %v", e.Handle)
}

// InvalidIntermediateCertsFileError is returned from SecureConnectToDefaultTPM if the specified file providing intermediate
// certificates for EK cert verification is invalid.
type InvalidEkCertFileError struct {
	msg string
}

func (e InvalidEkCertFileError) Error() string {
	return fmt.Sprintf("invalid EK certificate file: %s", e.msg)
}

// TPMVerificationError is returned from SecureConnectToDefaultTPM is the TPM doesn't contain a EK cert, or verification of the
// EK certificate fails, or the verified EK certificate doesn't belong to the TPM that is being connected to.
type TPMVerificationError struct {
	msg string
}

func (e TPMVerificationError) Error() string {
	return fmt.Sprintf("verification of the TPM failed: %s", e.msg)
}
