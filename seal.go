package fdeutil

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
)

const (
	currentVersion uint32 = 0
)

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
	rw, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("cannot open TPM device: %v", err)
	}
	defer rw.Close()

	// The object doesn't have the userWithAuth attribute set, so the auth value can only be used
	// for actions that require the admin role. There aren't any of those that we need, so set it to a
	// random 128-bit value and forget it.
	authValue := make([]byte, 16)
	_, err = rand.Read(authValue)
	if err != nil {
		return fmt.Errorf("cannot obtain random bytes for auth value: %v", err)
	}

	priv, pub, err := tpm2.Seal(rw, srkHandle, "", string(authValue), authPolicy, key)
	if err != nil {
		fmt.Errorf("cannot create sealed data object for key: %v", err)
	}

	// 5) Marshal the sealed key and auxilliary data to the supplied buf
	if err := binary.Write(buf, binary.LittleEndian, currentVersion); err != nil {
		return fmt.Errorf("cannot write version identifier to output buffer: %v", err)
	}

	writeSealedDataObjectPart := func(data []byte, label string) error {
		if err := binary.Write(buf, binary.LittleEndian, uint32(len(data))); err != nil {
			return fmt.Errorf("cannot write length of sealed data object %s part to output buffer: %v",
				label, err)
		}
		_, err := buf.Write(data)
		if err != nil {
			return fmt.Errorf("cannot write sealed data object %s part to output buffer: %v",
				label, err)
		}
		return nil
	}

	if err := writeSealedDataObjectPart(priv, "private"); err != nil {
		return err
	}
	if err := writeSealedDataObjectPart(pub, "public"); err != nil {
		return err
	}
	return nil
}
