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
	// ErrClearRequiresPPI is returned from ProvisionTPM and indicates that clearing the TPM must be performed via
	// the Physical Presence Interface.
	ErrClearRequiresPPI = errors.New("clearing requires the use of the Physical Presence Interface")

	// ErrProvisioning indicates that the TPM is not provisioned correctly for the requested operation. Please note
	// that other errors may also indicate an issue with incomplete provisioning.
	ErrProvisioning = errors.New("the TPM is not correctly provisioned")

	// ErrLockout is returned from any function when the TPM is in dictionary-attack lockout mode. Until
	// the TPM exits lockout mode, the key will need to be recovered via a mechanism that is independent of
	// the TPM (eg, a recovery key)
	ErrLockout = errors.New("the TPM is in DA lockout mode")

	// ErrPinFail is returned from SealedKeyObject.UnsealFromTPM if the provided PIN is incorrect.
	ErrPinFail = errors.New("the provided PIN is incorrect")
)

// TPMResourceExistsError is returned from any function that creates a persistent TPM resource if a resource already exists
// at the specified handle.
type TPMResourceExistsError struct {
	Handle tpm2.Handle
}

func (e TPMResourceExistsError) Error() string {
	return fmt.Sprintf("a resource already exists on the TPM at handle 0x%08x", e.Handle)
}

// InvalidKeyFileError indicates that the provided key data file is invalid. This error may also be returned in some
// scenarious where the TPM is incorrectly provisioned, but it isn't possible to determine whether the error is with
// the provisioning status or because the key data file is invalid.
type InvalidKeyFileError struct {
	msg string
}

func (e InvalidKeyFileError) Error() string {
	return fmt.Sprintf("invalid key data file: %s", e.msg)
}

// AuthFailError is returned when an authorization check fails. The provided handle indicates the resource for which authorization
// failed. Whilst the error normally indicates that the provided authorization value is incorrect, it may also be returned
// for other reasons that would cause a HMAC check failure, such as a communication failure between the host CPU and the TPM
// or the name of a resource on the TPM not matching the name of the ResourceContext passed to the function that failed - this
// latter issue can occur when using a resource manager if another process accesses the TPM and makes changes to persistent
// resources.
type AuthFailError struct {
	Handle tpm2.Handle
}

func (e AuthFailError) Error() string {
	return fmt.Sprintf("an authorization check failed for the hierarchy associated with %v", e.Handle)
}

// EkCertVerificationError is returned from SecureConnectToDefaultTPM if verification of the EK certificate against the built-in
// root CA certificates fails, or the EK certificate does not have the correct properties, or the supplied certificate data cannot
// be unmarshalled correctly because it is invalid.
type EkCertVerificationError struct {
	msg string
}

func (e EkCertVerificationError) Error() string {
	return fmt.Sprintf("cannot verify the endorsement key certificate: %s", e.msg)
}

// TPMVerificationError is returned from SecureConnectToDefaultTPM if the TPM cannot prove it is the device for which the
// supplied EK certificate was issued.
type TPMVerificationError struct {
	msg string
}

func (e TPMVerificationError) Error() string {
	return fmt.Sprintf("cannot verify that the TPM is the device for which the supplied EK certificate was issued: %s", e.msg)
}
