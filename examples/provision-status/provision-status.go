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
	"fmt"
	"os"

	"github.com/chrisccoulson/ubuntu-core-fde-utils"
)

func main() {
	tpm, err := fdeutil.ConnectToDefaultTPM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot acquire TPM context: %v", err)
		os.Exit(1)
	}
	defer tpm.Close()

	status, err := fdeutil.ProvisionStatus(tpm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot determine status: %v\n", err)
		os.Exit(1)
	}

	if status&fdeutil.AttrValidSRK > 0 {
		fmt.Println("Valid SRK found in TPM")
	} else {
		fmt.Println("** ERROR: TPM does not have a valid SRK **")
	}

	if status&fdeutil.AttrDAParamsOK > 0 {
		fmt.Println("TPM's DA parameters are correct")
	} else {
		fmt.Println("** ERROR: TPM's DA parameters are not the values set during provisioning **")
	}

	if status&fdeutil.AttrOwnerClearDisabled > 0 {
		fmt.Println("TPM does not allow clearing with the lockout hierarchy authorization")
	} else {
		fmt.Println("** ERROR: TPM allows clearing with the lockout hierarchy authorization **")
	}

	if status&fdeutil.AttrLockoutAuthSet > 0 {
		fmt.Println("The lockout hierarchy authorization is set")
	} else {
		fmt.Println("** ERROR: The lockout hierarchy authorization is not set **")
	}
}
