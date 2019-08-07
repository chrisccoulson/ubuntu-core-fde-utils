package main

import (
	"fmt"
	"os"

	"github.com/chrisccoulson/ubuntu-core-fde-utils"
)

func main() {
	status, err := fdeutil.ProvisionStatus()
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
