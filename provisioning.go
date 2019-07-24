package fdeutil

import (
	"errors"
	"fmt"
	"os"

	"github.com/chrisccoulson/go-tpm2"
)

const (
	ppiPath string = "/sys/class/tpm/tpm0/ppi/request"

	clearPPIRequest string = "5"
)

var (
	ErrClearRequiresPPI = errors.New("clearing requires the use of the Physical Presence Interface")

	srkTemplate = tpm2.Public{
		Type:    tpm2.AlgorithmRSA,
		NameAlg: tpm2.AlgorithmSHA256,
		Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin |
			tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params: tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: tpm2.AlgorithmAES,
					KeyBits:   tpm2.SymKeyBitsU{Sym: 128},
					Mode:      tpm2.SymModeU{Sym: tpm2.AlgorithmCFB}},
				Scheme:   tpm2.RSAScheme{Scheme: tpm2.AlgorithmNull},
				KeyBits:  2048,
				Exponent: 0}}}
)

func ProvisionTPM(lockoutAuth []byte) error {
	tcti, err := tpm2.OpenTPMDevice(tpmPath)
	if err != nil {
		return fmt.Errorf("cannot open TPM device: %v", err)
	}
	tpm, err := tpm2.NewTPMContext(tcti)
	if err != nil {
		return fmt.Errorf("cannot create new TPM context: %v", err)
	}
	defer tpm.Close()

	props, err := tpm.GetCapabilityTPMProperties(tpm2.PropertyPermanent, 1)
	if err != nil {
		return fmt.Errorf("cannot request permanent properties: %v", err)
	}

	p := tpm2.PermanentAttributes(props[0].Value)
	if p&tpm2.AttrLockoutAuthSet > 0 || p&tpm2.AttrDisableClear > 0 {
		return ErrClearRequiresPPI
	}

	if err := tpm.Clear(tpm2.HandleLockout, nil); err != nil {
		return fmt.Errorf("cannot clear the TPM: %v", err)
	}

	srkContext, _, _, _, _, _, err := tpm.CreatePrimary(tpm2.HandleOwner, nil, &srkTemplate, nil, nil, nil)
	if err != nil {
		return fmt.Errorf("cannot create storage root key: %v", err)
	}
	defer tpm.FlushContext(srkContext)

	if _, err := tpm.EvictControl(tpm2.HandleOwner, srkContext, srkHandle, nil); err != nil {
		return fmt.Errorf("cannot make storage root key persistent: %v", err)
	}

	if err := tpm.DictionaryAttackParameters(tpm2.HandleLockout, 32, 7200, 86400, nil); err != nil {
		return fmt.Errorf("cannot configure DA parameters: %v", err)
	}

	if err := tpm.ClearControl(tpm2.HandleLockout, true, nil); err != nil {
		return fmt.Errorf("cannot disable owner clear: %v", err)
	}

	if err := tpm.HierarchyChangeAuth(tpm2.HandleLockout, tpm2.Auth(lockoutAuth), nil); err != nil {
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
