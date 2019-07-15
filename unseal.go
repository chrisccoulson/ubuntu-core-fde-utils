package fdeutil

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
)

// This function prototype will be extended to take a buffer containing a separate PIN object, and a PIN if one
// is required by the policy
func UnsealKeyFromTPM(buf io.Reader) ([]byte, error) {
	// 1) Unmarshal the sealed data object and auxilliary data
	var version uint32
	if err := binary.Read(buf, binary.LittleEndian, &version); err != nil {
		return nil, fmt.Errorf("cannot read version identifier from input buffer: %v", err)
	}

	if version != currentVersion {
		return nil, fmt.Errorf("cannot unseal key because the version identifier is an unexpected value")
	}

	readSealedDataObjectPart := func(label string) ([]byte, error) {
		var size uint32
		if err := binary.Read(buf, binary.LittleEndian, &size); err != nil {
			return nil, fmt.Errorf("cannot read size of sealed data object %s part from input " +
				"buffer: %v", label, err)
		}
		out := make([]byte, size)
		n, err := buf.Read(out)
		if err != nil {
			return nil, fmt.Errorf("cannot read sealed data object %s part from input buffer: %v",
				label, err)
		}
		if n < int(size) {
			return nil, fmt.Errorf("cannot read sealed data object %s part from input buffer: " +
				"insufficient number of bytes read", label)
		}
		return out, nil
	}

	priv, err := readSealedDataObjectPart("private")
	if err != nil {
		return nil, err
	}
	pub, err := readSealedDataObjectPart("public")
	if err != nil {
		return nil, err
	}

	// 2) Load objects in to TPM
	rw, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open TPM device: %v", err)
	}
	defer rw.Close()

	keyHandle, _, err := tpm2.Load(rw, srkHandle, "", pub, priv)
	if err != nil {
		return nil, fmt.Errorf("cannot load sealed data object in to TPM: %v", err)
	}
	defer tpm2.FlushContext(rw, keyHandle)

	// 3) Begin and execute policy session
	//  TODO: Actually execute policy assertions
	sessionHandle, _, err := tpm2.StartAuthSession(rw, tpm2.HandleNull, tpm2.HandleNull, make([]byte, 16),
		nil, tpm2.SessionPolicy, tpm2.AlgNull, tpm2.AlgSHA256)
	if err != nil {
		return nil, fmt.Errorf("cannot start policy session: %v", err)
	}
	defer tpm2.FlushContext(rw, sessionHandle)

	// 4) Unseal
	key, err := tpm2.UnsealWithSession(rw, sessionHandle, keyHandle, "")
	if err != nil {
		return nil, fmt.Errorf("cannot unseal key: %v", err)
	}

	return key, nil
}
