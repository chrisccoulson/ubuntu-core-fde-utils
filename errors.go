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
	ErrClearRequiresPPI = errors.New("clearing requires the use of the Physical Presence Interface")

	ErrProvisioning  = errors.New("the TPM is not correctly provisioned")
	ErrKeyFileExists = errors.New("a key data file already exists at the specified path")

	ErrOwnerAuthFail = errors.New("an authorization check for the storage hierarchy failed")
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
