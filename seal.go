package fdeutil

import (
	"fmt"
	"io"

	"github.com/chrisccoulson/go-tpm2"
)

const (
	currentVersion uint32 = 0
)

// TODO: This function prototype will be extended to take policy inputs and a buffer containing a separate PIN
// object that will be used to calculate a policy digest
func SealKeyToTPM(tpm tpm2.TPMContext, buf io.Writer, key []byte) error {
	if len(key) != 64 {
		return fmt.Errorf("expected a key length of 512 bits (got %d)", len(key)*8)
	}

	// 1) Convert policy inputs in to individual event digests
	//  TODO

	// 2) Use event digests, the event log and GRUB data to generate PCR digests
	//  TODO

	// 3) Use the PCR digests to generate a single policy digest
	//  TODO
	authPolicy := make([]byte, 32)

	// 4) Seal the key to the TPM with the calculated policy digest
	template := tpm2.Public{
		Type:       tpm2.AlgorithmKeyedHash,
		NameAlg:    tpm2.AlgorithmSHA256,
		Attrs:      tpm2.AttrFixedTPM | tpm2.AttrFixedParent,
		AuthPolicy: authPolicy,
		Params: tpm2.PublicParamsU{
			KeyedHashDetail: &tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.AlgorithmNull}}}}

	sensitive := tpm2.SensitiveCreate{Data: key}

	srkContext, err := tpm.WrapHandle(srkHandle)
	if err != nil {
		return fmt.Errorf("cannot create context for SRK handle: %v", err)
	}

	// Create a session for command parameter encryption
	sessionContext, err := tpm.StartAuthSession(srkContext, nil, tpm2.SessionTypeHMAC, &paramEncryptAlg,
		tpm2.AlgorithmSHA256, nil)
	if err != nil {
		return fmt.Errorf("cannot create session for encryption: %v", err)
	}
	defer tpm.FlushContext(sessionContext)

	// Now create the sealed data object
	session := tpm2.Session{Context: sessionContext, Attrs: tpm2.AttrCommandEncrypt}
	priv, pub, _, _, _, err := tpm.Create(srkContext, &sensitive, &template, nil, nil, nil, &session)
	if err != nil {
		return fmt.Errorf("cannot create sealed data object for key: %v", err)
	}

	// 5) Marshal the sealed key and auxilliary data to the supplied buf
	if err := tpm2.MarshalToWriter(buf, currentVersion, priv, pub); err != nil {
		return fmt.Errorf("cannot marshal sealed data object to output buffer: %v", err)
	}

	return nil
}
