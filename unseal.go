package fdeutil

import (
	"errors"
	"fmt"
	"io"

	"github.com/chrisccoulson/go-tpm2"
)

var (
	ErrLockout = errors.New("the TPM is in DA lockout mode")
	ErrPinFail = errors.New("the provided PIN is incorrect")
)

func UnsealKeyFromTPM(tpm tpm2.TPMContext, buf io.Reader, pin string) ([]byte, error) {
	props, err := tpm.GetCapabilityTPMProperties(tpm2.PropertyPermanent, 1)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch properties from TPM: %v", err)
	}

	if tpm2.PermanentAttributes(props[0].Value)&tpm2.AttrInLockout > 0 {
		return nil, ErrLockout
	}

	// Load the key data
	var data keyData
	keyContext, pinContext, err := data.loadAndIntegrityCheck(buf, tpm, false)
	if err != nil {
		return nil, fmt.Errorf("cannot load key data: %v", err)
	}
	defer func() {
		tpm.FlushContext(keyContext)
		tpm.FlushContext(pinContext)
	}()

	// Begin and execute policy session
	srkContext, err := tpm.WrapHandle(srkHandle)
	if err != nil {
		return nil, fmt.Errorf("cannot create context for SRK handle: %v", err)
	}

	sessionContext, err :=
		tpm.StartAuthSession(srkContext, nil, tpm2.SessionTypePolicy, &paramEncryptAlg,
			tpm2.AlgorithmSHA256, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot start policy session: %v", err)
	}
	defer tpm.FlushContext(sessionContext)

	if err := executePolicySession(tpm, sessionContext, pinContext, data.AuxData.PolicyData, pin); err != nil {
		switch e := err.(type) {
		case policySecretError:
			switch e := e.err.(type) {
			case tpm2.TPMSessionError:
				if e.Code == tpm2.ErrorAuthFail {
					return nil, ErrPinFail
				}
			}
		}
		return nil, fmt.Errorf("cannot complete execution of policy session: %v", err)
	}

	// Unseal
	session := tpm2.Session{Context: sessionContext, Attrs: tpm2.AttrResponseEncrypt}
	key, err := tpm.Unseal(keyContext, &session)
	if err != nil {
		return nil, fmt.Errorf("cannot unseal key: %v", err)
	}

	return key, nil
}
