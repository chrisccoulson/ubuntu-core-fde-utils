// +build !arm64

package fdeutil

import (
	"errors"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2"
)

const (
	ppiPath string = "/sys/class/tpm/tpm0/ppi/request"

	permanentProps uint32 = 0x00000200
	lockoutAuthSet uint32 = 1 << 2
	disableClear   uint32 = 1 << 8

	clearPPIRequest string = "5"
)

var (
	ErrClearRequiresPPI = errors.New("clearing requires the use of the Physical Presence Interface")

	srkTemplate = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: nil,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB},
			KeyBits:    2048,
			Exponent:   0,
			ModulusRaw: make([]byte, 256)}}
)

func ProvisionTPM(lockoutAuth []byte) error {
	rw, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("cannot open TPM device: %v", err)
	}
	defer rw.Close()

	c, _, err := tpm2.GetCapability(rw, tpm2.CapabilityTPMProperties, 1, permanentProps)
	if err != nil {
		return fmt.Errorf("cannot request permanent properties: %v", err)
	}

	p := c[0].(tpm2.TaggedProperty).Value
	if p&lockoutAuthSet > 0 || p&disableClear > 0 {
		return ErrClearRequiresPPI
	}

	if err := tpm2.Clear(rw, tpm2.HandleLockout, ""); err != nil {
		return fmt.Errorf("cannot clear the TPM: %v", err)
	}

	h, _, err := tpm2.CreatePrimary(rw, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate)
	if err != nil {
		return fmt.Errorf("cannot create storage root key: %v", err)
	}
	defer tpm2.FlushContext(rw, h)

	if err := tpm2.EvictControl(rw, "", tpm2.HandleOwner, h, srkHandle); err != nil {
		return fmt.Errorf("cannot make storage root key persistent: %v", err)
	}

	if err := tpm2.SetDictionaryAttackParameters(rw, 32, 7200, 86400, ""); err != nil {
		return fmt.Errorf("cannot configure DA parameters: %v", err)
	}

	if err := tpm2.ClearControl(rw, tpm2.HandleLockout, true, ""); err != nil {
		return fmt.Errorf("cannot disable owner clear: %v", err)
	}

	if err := tpm2.HierarchyChangeAuth(rw, tpm2.HandleLockout, "", string(lockoutAuth)); err != nil {
		return fmt.Errorf("cannot set the lockout hierarchy authorization value: %v", err)
	}

	return nil
}

func RequestTPMClearUsingPPI() error {
	f, err := os.OpenFile(ppiPath, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("cannot open request handle: %v", err)
	}
	defer f.Close()

	if _, err := f.WriteString(clearPPIRequest); err != nil {
		return fmt.Errorf("cannot submit request: %v", err)
	}

	return nil
}
