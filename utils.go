package fdeutil

import (
	"github.com/chrisccoulson/go-tpm2"
)

func isAuthFailError(err error) bool {
	switch e := err.(type) {
	case tpm2.TPMSessionError:
		switch e.Code {
		case tpm2.ErrorAuthFail: // With DA implications
			return true
		case tpm2.ErrorBadAuth: // Without DA implications
			return true
		}
	}
	return false
}

func isLockoutError(err error) bool {
	switch e := err.(type) {
	case tpm2.TPMWarning:
		if e.Code == tpm2.WarningLockout {
			return true
		}
	}
	return false
}

func isHandleError(err error) bool {
	switch e := err.(type) {
	case tpm2.TPMHandleError:
		if e.Code == tpm2.ErrorHandle {
			return true
		}
	}
	return false
}
