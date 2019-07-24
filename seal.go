package fdeutil

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/chrisccoulson/go-tpm2"
)

const (
	currentVersion uint32 = 0
)

var ()

// TODO: This function prototype will be extended to take policy inputs and a buffer containing a separate PIN
// object that will be used to calculate a policy digest
func SealKeyToTPM(buf io.Writer, key []byte) error {
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
	tcti, err := tpm2.OpenTPMDevice(tpmPath)
	if err != nil {
		return fmt.Errorf("cannot open TPM device: %v", err)
	}
	tpm, err := tpm2.NewTPMContext(tcti)
	if err != nil {
		return fmt.Errorf("cannot create new TPM context: %v", err)
	}
	defer tpm.Close()

	template := tpm2.Public{
		Type:       tpm2.AlgorithmKeyedHash,
		NameAlg:    tpm2.AlgorithmSHA256,
		Attrs:      tpm2.AttrFixedTPM | tpm2.AttrFixedParent,
		AuthPolicy: authPolicy,
		Params: tpm2.PublicParamsU{
			KeyedHashDetail: &tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.AlgorithmNull}}}}

	// The object doesn't have the userWithAuth attribute set, so the auth value can only be used
	// for actions that require the admin role. There aren't any of those that we need, so set it to a
	// random 128-bit value and forget it.
	authValue := make([]byte, 16)
	_, err = rand.Read(authValue)
	if err != nil {
		return fmt.Errorf("cannot obtain random bytes for auth value: %v", err)
	}

	sensitive := tpm2.SensitiveCreate{Data: key, UserAuth: authValue}

	srkContext, err := tpm.WrapHandle(srkHandle)
	if err != nil {
		return fmt.Errorf("cannot create context for SRK handle: %v", err)
	}

	priv, pub, _, _, _, err := tpm.Create(srkContext, &sensitive, &template, nil, nil, nil)
	if err != nil {
		return fmt.Errorf("cannot create sealed data object for key: %v", err)
	}

	// 5) Marshal the sealed key and auxilliary data to the supplied buf
	if err := tpm2.MarshalToWriter(buf, currentVersion, priv, pub); err != nil {
		return fmt.Errorf("cannot marshal sealed data object to output buffer: %v", err)
	}

	return nil
}
