package fdeutil

import (
	"fmt"
	"io"

	"github.com/chrisccoulson/go-tpm2"
)

// This function prototype will be extended to take a buffer containing a separate PIN object, and a PIN if one
// is required by the policy
func UnsealKeyFromTPM(buf io.Reader) ([]byte, error) {
	// 1) Unmarshal the sealed data object and auxilliary data
	var version uint32
	var priv tpm2.Private
	var pub tpm2.Public
	if err := tpm2.UnmarshalFromReader(buf, &version, &priv, &pub); err != nil {
		return nil, fmt.Errorf("cannot unmarshal sealed data object from buffer: %v", err)
	}

	if version != currentVersion {
		return nil, fmt.Errorf("cannot unseal key because the version identifier is an unexpected value")
	}

	// 2) Load objects in to TPM
	tcti, err := tpm2.OpenTPMDevice(tpmPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open TPM device: %v", err)
	}
	tpm, err := tpm2.NewTPMContext(tcti)
	if err != nil {
		return nil, fmt.Errorf("cannot create new TPM context: %v", err)
	}
	defer tpm.Close()

	srkContext, err := tpm.WrapHandle(srkHandle)
	if err != nil {
		return nil, fmt.Errorf("cannot create context for SRK handle: %v", err)
	}

	keyContext, _, err := tpm.Load(srkContext, priv, &pub, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot load sealed data object in to TPM: %v", err)
	}
	defer tpm.FlushContext(keyContext)

	// 3) Begin and execute policy session
	//  TODO: Actually execute policy assertions
	sessionContext, err :=
		tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.AlgorithmSHA256, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot start policy session: %v", err)
	}
	defer tpm.FlushContext(sessionContext)

	// 4) Unseal
	key, err := tpm.Unseal(keyContext, &tpm2.Session{Handle: sessionContext})
	if err != nil {
		return nil, fmt.Errorf("cannot unseal key: %v", err)
	}

	return key, nil
}
