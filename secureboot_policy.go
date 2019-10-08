package fdeutil

import (
	"bytes"
	"crypto/x509"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/chrisccoulson/go-tpm2"
	"github.com/chrisccoulson/tcglog-parser"
	"github.com/fullsailor/pkcs7"
)

type eventClass int

const (
	eventClassUnclassified eventClass = iota
	eventClassDb
	eventClassDbx
	eventClassDriverVerification
	eventClassDriverAndInitialAppVerification
	eventClassInitialAppVerification
	eventClassAppVerification
)

const (
	dbName      string = "db"
	dbxName     string = "dbx"
	sbStateName string = "SecureBoot"

	mokListName    string = "MokList"
	mokSbStateName string = "MokSBState"
	shimName       string = "Shim"

	eventLogPath = "/sys/kernel/security/tpm0/binary_bios_measurements"

	dbPath      string = "/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f"
	dbxPath     string = "/sys/firmware/efi/efivars/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f"
	mokListPath string = "/sys/firmware/efi/efivars/MokListRT-605dab50-e046-4300-abb6-3dd810dd8b23"

	winCertTypePKCSSignedData uint16 = 2

	uefiDriverPCR      = 2
	bootManagerCodePCR = 4

	returningFromEfiApplicationEvent string = "Returning from EFI Application from Boot Option"
)

var (
	shimGuid = tcglog.EFIGUID{A: 0x605dab50, B: 0xe046, C: 0x4300, D: 0xabb6,
		E: [...]uint8{0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23}}
	efiGlobalVariableGuid = tcglog.EFIGUID{A: 0x8be4df61, B: 0x93ca, C: 0x11d2, D: 0xaa0d,
		E: [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}}
	efiImageSecurityDatabaseGuid = tcglog.EFIGUID{A: 0xd719b2cb, B: 0x3d3a, C: 0x4596, D: 0xa3bc,
		E: [...]uint8{0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f}}

	efiCertX509Guid = tcglog.EFIGUID{A: 0xa5c059a1, B: 0x94e4, C: 0x4aa7, D: 0x87b5,
		E: [...]uint8{0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72}}
)

var (
	dbPathForTesting       string
	dbxPathForTesting      string
	eventLogPathForTesting string
)

type classifiedEvent struct {
	class eventClass
	event *tcglog.ValidatedEvent
}

// classifySecureBootEvents iterates over a sequence of events and determines which events correspond to
// measurements of db, dbx and which measurement corresponds to verification of the initial boot executable.
// It returns a list of classified events for the secure boot policy PCR (#7)
func classifySecureBootEvents(events []*tcglog.ValidatedEvent) ([]classifiedEvent, error) {
	var out []classifiedEvent
	seenInitialAppVerificationEvent := false

	for _, e := range events {
		switch e.Event.PCRIndex {
		case uefiDriverPCR:
			if e.Event.EventType == tcglog.EventTypeEFIBootServicesDriver ||
				e.Event.EventType == tcglog.EventTypeEFIRuntimeServicesDriver {
				if len(out) == 0 {
					continue
				}
				prev := out[len(out)-1]
				if prev.event.Event.EventType != tcglog.EventTypeEFIVariableAuthority {
					continue
				}
				if prev.class == eventClassUnclassified {
					out[len(out)-1].class = eventClassDriverVerification
				}
			}
		case bootManagerCodePCR:
			// Identify the event that corresponds to the verification of the initial EFI boot
			// executable by looking for the EV_EFI_BOOT_SERVICES_APPLICATION event recorded to PCR4.
			// This is recorded for every boot attempt after the verification event is recorded to
			// PCR7
			if e.Event.EventType == tcglog.EventTypeEFIBootServicesApplication &&
				!seenInitialAppVerificationEvent {
				if len(out) == 0 {
					return nil, fmt.Errorf("%s boot manager code event occurred without any "+
						"secure boot policy events being recorded", e.Event.EventType)
				}
				prev := out[len(out)-1]
				if prev.event.Event.EventType != tcglog.EventTypeEFIVariableAuthority {
					return nil, fmt.Errorf("%s boot manager code event wasn't preceeded by "+
						"a %s secure boot policy event", e.Event.EventType,
						tcglog.EventTypeEFIVariableAuthority)
				}
				seenInitialAppVerificationEvent = true
				switch prev.class {
				case eventClassUnclassified:
					// The preceding verification event is exclusive to the initial EFI boot
					// executable
					out[len(out)-1].class = eventClassInitialAppVerification
				case eventClassDriverVerification:
					// The preceding verification event isn't exclusive to the initial EFI
					// boot executable
					out[len(out)-1].class = eventClassDriverAndInitialAppVerification
				}
			}
		case secureBootPCR:
			c := eventClassUnclassified

			switch e.Event.EventType {
			case tcglog.EventTypeEFIVariableDriverConfig:
				efiVarData := e.Event.Data.(*tcglog.EFIVariableEventData)
				if efiVarData.VariableName == efiImageSecurityDatabaseGuid {
					switch efiVarData.UnicodeName {
					case dbName:
						c = eventClassDb
					case dbxName:
						c = eventClassDbx
					}
				}
			case tcglog.EventTypeEFIVariableAuthority:
				if seenInitialAppVerificationEvent {
					c = eventClassAppVerification
				}
			}

			out = append(out, classifiedEvent{class: c, event: e})
		default:
			continue
		}
	}

	if !seenInitialAppVerificationEvent {
		return nil, errors.New("cannot determine verification event for initial boot application")
	}

	return out, nil
}

func decodeEFIGUID(r io.Reader) (*tcglog.EFIGUID, error) {
	var out tcglog.EFIGUID
	if err := binary.Read(r, binary.LittleEndian, &out.A); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &out.B); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &out.C); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &out.D); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, out.E[:]); err != nil {
		return nil, err
	}
	return &out, nil
}

type efiSignatureData struct {
	signatureType tcglog.EFIGUID
	owner         tcglog.EFIGUID
	data          []byte
}

func (e *efiSignatureData) encode(buf io.Writer) error {
	if err := e.owner.Encode(buf); err != nil {
		return fmt.Errorf("cannot encode signature owner: %v", err)
	}
	if _, err := buf.Write(e.data); err != nil {
		return fmt.Errorf("cannot write signature data: %v", err)
	}
	return nil
}

// iterateSecureBootDb iterates the contents of a secure boot database, calling fn on each EFI_SIGNATURE_DATA
// entry
func iterateSecureBootDb(r io.ReaderAt, fn func(*tcglog.EFIGUID, *io.SectionReader, *io.SectionReader,
	bool) (bool, error)) error {
	offset := int64(0)
	// Iterate over each EFI_SIGNATURE_LIST entry
	for {
		sr := io.NewSectionReader(r, offset, (1<<63)-1-offset)

		// Decode EFI_SIGNATURE_LIST.SignatureType
		signatureType, err := decodeEFIGUID(sr)
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("cannot decode SignatureType from EFI_SIGNATURE_LIST: %v", err)
		}

		// Decode EFI_SIGNATURE_LIST.SignatureListSize, which indicates the size of the entire
		// EFI_SIGNATURE_LIST, including all of the EFI_SIGNATURE_DATA entries.
		var signatureListSize uint32
		if err := binary.Read(sr, binary.LittleEndian, &signatureListSize); err != nil {
			return fmt.Errorf("cannot read SignatureListSize from EFI_SIGNATURE_LIST: %v", err)
		}

		// Decode EFI_SIGNATURE_LIST.SignatureHeaderSize, which indicates the size of the optional
		// header data between the core EFI_SIGNATURE_LIST fields and the EFI_SIGNATURE_DATA entries.
		// Always zero for the signature types we care about
		var signatureHeaderSize uint32
		if err := binary.Read(sr, binary.LittleEndian, &signatureHeaderSize); err != nil {
			return fmt.Errorf("cannot read SignatureHeaderSize from EFI_SIGNATURE_LIST: %v", err)
		}

		// Decode EFI_SIGNATURE_LIST.SignatureSize, which indicates the size of each EFI_SIGNATURE_DATA
		// entry
		var signatureSize uint32
		if err := binary.Read(sr, binary.LittleEndian, &signatureSize); err != nil {
			return fmt.Errorf("cannot read SignatureSize from EFI_SIGNATURE_LIST: %v", err)
		}

		headerStart, _ := sr.Seek(0, io.SeekCurrent)
		// Obtain a SectionReader for the optional header data
		hsr := io.NewSectionReader(sr, headerStart, int64(signatureHeaderSize))

		// sigListHeaderSize is the size of the EFI_SIGNATURE_LIST structure, up to the start of the
		// EFI_SIGNATURE_DATA entries
		sigListHeaderSize := headerStart + int64(signatureHeaderSize)

		// Calculate the number of EFI_SIGNATURE_DATA entries
		numOfSignatures := (int64(signatureListSize) - sigListHeaderSize) / int64(signatureSize)

		// Iterate over each EFI_SIGNATURE_DATA entry
		for i := int64(0); i < numOfSignatures; i++ {
			ssr := io.NewSectionReader(sr, sigListHeaderSize+(i*int64(signatureSize)),
				int64(signatureSize))
			final := i == numOfSignatures-1
			if cont, err := fn(signatureType, hsr, ssr, final); err != nil {
				return fmt.Errorf("cannot process EFI_SIGNATURE_DATA at index %d: %v", i, err)
			} else if !cont {
				return nil
			}
		}

		// Advance to the next EFI_SIGNATURE_LIST entry
		offset += int64(signatureListSize)
	}
	return nil
}

func decodeSecureBootDb(r io.ReaderAt) ([]*efiSignatureData, error) {
	var out []*efiSignatureData

	err := iterateSecureBootDb(r, func(t *tcglog.EFIGUID, h, s *io.SectionReader, unused bool) (bool, error) {
		// Decode EFI_SIGNATURE_DATA.SignatureOwner
		signatureOwner, err := decodeEFIGUID(s)
		if err != nil {
			return false, fmt.Errorf("cannot decode SignatureOwner: %v", err)
		}

		// Obtain and decode the X509 certificate
		data, err := ioutil.ReadAll(s)
		if err != nil {
			return false, fmt.Errorf("cannot obtain contents: %v", err)
		}

		out = append(out, &efiSignatureData{signatureType: *t, owner: *signatureOwner, data: data})
		return true, nil
	})

	if err != nil {
		return nil, err
	}

	return out, nil
}

type secureBootDb struct {
	variableName tcglog.EFIGUID
	unicodeName  string
	signatures   []*efiSignatureData
}

type secureBootDbSet struct {
	uefiDb secureBootDb
	mokDb  secureBootDb
	shimDb secureBootDb
}

type secureBootPolicyGen struct {
	alg    tpm2.AlgorithmId
	params *SealParams

	dbStack  []*secureBootDbSet
	pcrStack []tpm2.Digest

	firmwareVerificationEvents []tpm2.DigestList
	shimVerificationEvents     []tpm2.DigestList

	outputDigests tpm2.DigestList
}

func (g *secureBootPolicyGen) enterDbScope() {
	newDbSet := &secureBootDbSet{}
	if len(g.dbStack) > 0 {
		top := g.dbStack[len(g.dbStack)-1]
		newDbSet.uefiDb = top.uefiDb
		newDbSet.mokDb = top.mokDb
		newDbSet.shimDb = top.shimDb
	}
	g.dbStack = append(g.dbStack, newDbSet)
}

func (g *secureBootPolicyGen) exitDbScope() {
	g.dbStack = g.dbStack[0 : len(g.dbStack)-1]
}

func (g *secureBootPolicyGen) dbSet() *secureBootDbSet {
	return g.dbStack[len(g.dbStack)-1]
}

func (g *secureBootPolicyGen) enterMeasurementScope() {
	newPcrScope := make(tpm2.Digest, getDigestSize(g.alg))
	if len(g.pcrStack) > 0 {
		copy(newPcrScope, g.pcrStack[len(g.pcrStack)-1])
	}
	g.pcrStack = append(g.pcrStack, newPcrScope)

	newFVScope := make(tpm2.DigestList, 0)
	if len(g.firmwareVerificationEvents) > 0 {
		top := g.firmwareVerificationEvents[len(g.firmwareVerificationEvents)-1]
		newFVScope = make(tpm2.DigestList, len(top))
		copy(newFVScope, top)
	}
	g.firmwareVerificationEvents = append(g.firmwareVerificationEvents, newFVScope)

	if len(g.shimVerificationEvents) > 0 {
		top := g.shimVerificationEvents[len(g.shimVerificationEvents)-1]
		newShimScope := make(tpm2.DigestList, len(top))
		copy(newShimScope, top)
		g.shimVerificationEvents = append(g.shimVerificationEvents, newShimScope)
	}
}

func (g *secureBootPolicyGen) exitMeasurementScope() {
	if len(g.shimVerificationEvents) > 0 {
		g.shimVerificationEvents = g.shimVerificationEvents[0 : len(g.shimVerificationEvents)-1]
	}
	g.firmwareVerificationEvents = g.firmwareVerificationEvents[0 : len(g.firmwareVerificationEvents)-1]
	g.pcrStack = g.pcrStack[0 : len(g.pcrStack)-1]
}

func (g *secureBootPolicyGen) extendMeasurement(digest tpm2.Digest) {
	top := g.pcrStack[len(g.pcrStack)-1]

	h := hashAlgToGoHash(g.alg)
	h.Write(top)
	h.Write(digest)

	copy(top, h.Sum(nil))
}

func (g *secureBootPolicyGen) extendVerificationMeasurement(digest tpm2.Digest, mode OSComponentLoadType) {
	var digests *tpm2.DigestList
	switch mode {
	case FirmwareLoad:
		digests = &g.firmwareVerificationEvents[len(g.firmwareVerificationEvents)-1]
	case DirectLoadWithShimVerify:
		digests = &g.shimVerificationEvents[len(g.shimVerificationEvents)-1]
	}
	g.extendMeasurement(digest)
	*digests = append(*digests, digest)
}

func (g *secureBootPolicyGen) extendVerificationMeasurementIfUnique(digest tpm2.Digest,
	mode OSComponentLoadType) {
	var digests *tpm2.DigestList
	switch mode {
	case FirmwareLoad:
		digests = &g.firmwareVerificationEvents[len(g.firmwareVerificationEvents)-1]
	case DirectLoadWithShimVerify:
		digests = &g.shimVerificationEvents[len(g.shimVerificationEvents)-1]
	}
	for _, d := range *digests {
		if bytes.Equal(d, digest) {
			return
		}
	}
	g.extendVerificationMeasurement(digest, mode)
}

func (g *secureBootPolicyGen) enterShimScope() {
	g.shimVerificationEvents = append(g.shimVerificationEvents, make([]tpm2.Digest, 0))
}

func (g *secureBootPolicyGen) exitShimScope() {
	g.shimVerificationEvents = g.shimVerificationEvents[0 : len(g.shimVerificationEvents)-1]
}

func (g *secureBootPolicyGen) processSecureBootDb(db []byte, events []classifiedEvent) error {
	// Compute and extend a measurement for this db
	data := tcglog.EFIVariableEventData{
		VariableName: efiImageSecurityDatabaseGuid,
		UnicodeName:  dbName,
		VariableData: db}
	hash := hashAlgToGoHash(g.alg)
	if err := data.Encode(hash); err != nil {
		return fmt.Errorf("cannot encode EFI_VARIABLE_DATA: %v", err)
	}
	g.extendMeasurement(hash.Sum(nil))

	// Enter a new secure boot DB set scope
	g.enterDbScope()
	defer g.exitDbScope()

	// Decode this db and update the secure boot DB set
	signatures, err := decodeSecureBootDb(bytes.NewReader(db))
	if err != nil {
		return fmt.Errorf("cannot decode secure boot db: %v", err)
	}
	g.dbSet().uefiDb = secureBootDb{variableName: efiImageSecurityDatabaseGuid, unicodeName: dbName,
		signatures: signatures}

	// Continue replaying events
	if err := g.processEvents(events); err != nil {
		return fmt.Errorf("cannot process subsequent events from event log: %v", err)
	}

	return nil
}

func (g *secureBootPolicyGen) processSecureBootDbx(dbx []byte, events []classifiedEvent) error {
	// Compute and extend a measurement for this dbx
	data := tcglog.EFIVariableEventData{
		VariableName: efiImageSecurityDatabaseGuid,
		UnicodeName:  dbxName,
		VariableData: dbx}
	hash := hashAlgToGoHash(g.alg)
	if err := data.Encode(hash); err != nil {
		return fmt.Errorf("cannot encode EFI_VARIABLE_DATA: %v", err)
	}
	g.extendMeasurement(hash.Sum(nil))

	// Continue replaying events
	if err := g.processEvents(events); err != nil {
		return fmt.Errorf("cannot process subsequent events from event log: %v", err)
	}

	return nil
}

func (g *secureBootPolicyGen) processPeBinaryVerification(r io.ReaderAt, mode OSComponentLoadType) error {
	if mode == DirectLoadWithShimVerify && len(g.shimVerificationEvents) == 0 {
		return errors.New("shim verification specified without being preceeded by a shim executable")
	}

	pefile, err := pe.NewFile(r)
	if err != nil {
		return fmt.Errorf("cannot decode PE binary: %v", err)
	}

	if pefile.OptionalHeader == nil {
		// Work around debug/pe not handling variable length optional headers - see
		// https://github.com/golang/go/commit/3b92f36d15c868e856be71c0fadfc7ff97039b96
		// We copy the required functionality from that commit in to this file for now.
		h, err := tryHarderToGetOptionalPeHeader(pefile, r)
		if err != nil {
			return fmt.Errorf("cannot decode optional header: %v", err)
		}
		pefile.OptionalHeader = h
	}

	// Obtain security directory entry from optional header
	var dd *pe.DataDirectory
	switch oh := pefile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if oh.NumberOfRvaAndSizes < 5 {
			return errors.New("cannot obtain security directory entry: invalid number of data " +
				"directories")
		}
		dd = &oh.DataDirectory[4]
	case *pe.OptionalHeader64:
		if oh.NumberOfRvaAndSizes < 5 {
			return errors.New("cannot obtain security directory entry: invalid number of data " +
				"directories")
		}
		dd = &oh.DataDirectory[4]
	default:
		return errors.New("cannot obtain security directory entry: no optional header")
	}

	// Create a reader for the security directory entry, which points to a WIN_CERTIFICATE struct
	secReader := io.NewSectionReader(r, int64(dd.VirtualAddress), int64(dd.Size))

	// Obtain the length of the certificate, including the size of WIN_CERTIFICATE
	var dwLength uint32
	if err := binary.Read(secReader, binary.LittleEndian, &dwLength); err != nil {
		return fmt.Errorf("cannot read signature length: %v", err)
	}
	// Skip over WIN_CERTIFICATE.wRevision
	if _, err := secReader.Seek(2, io.SeekCurrent); err != nil {
		return fmt.Errorf("cannot advance beyond signature revision level: %v", err)
	}
	// Obtain WIN_CERTIFICATE.wCertificateType
	var wCertificateType uint16
	if err := binary.Read(secReader, binary.LittleEndian, &wCertificateType); err != nil {
		return fmt.Errorf("cannot read signature type: %v", err)
	}
	if wCertificateType != winCertTypePKCSSignedData {
		return fmt.Errorf("unexpected value %d for wCertificateType: not an Authenticode signature",
			wCertificateType)
	}
	// Allocate a byte slice and fill it with the entire signature
	data := make([]byte, dwLength-8)
	if _, err := io.ReadFull(secReader, data); err != nil {
		return fmt.Errorf("cannot read signature: %v", err)
	}

	// Decode the signature
	p7, err := pkcs7.Parse(data)
	if err != nil {
		return fmt.Errorf("cannot decode signature: %v", err)
	}

	// Grab the certificate for the signing key
	signer := p7.GetOnlySigner()
	if signer == nil {
		return errors.New("cannot obtain signer certificate from signature")
	}

	// Look for the issuing authority in the UEFI db, and if the verifier is shim, also look in MOK db and
	// at shim's vendor cert
	dbs := []*secureBootDb{&g.dbSet().uefiDb}
	if mode == DirectLoadWithShimVerify {
		dbs = append(dbs, &g.dbSet().mokDb, &g.dbSet().shimDb)
	}

	var root *efiSignatureData
	var rootDb *secureBootDb
Outer:
	for _, db := range dbs {
		for _, s := range db.signatures {
			// Ignore signatures that aren't X509 certificates
			if s.signatureType != efiCertX509Guid {
				continue
			}

			if bytes.Equal(s.data, signer.Raw) {
				// The signing certificate is actually the root in the DB
				root = s
				rootDb = db
				break Outer
			}

			c, err := x509.ParseCertificate(s.data)
			if err != nil {
				continue
			}

			if err := signer.CheckSignatureFrom(c); err == nil {
				// The signing certificate was issued by this root
				root = s
				rootDb = db
				break Outer
			}
		}
	}

	if root == nil {
		// XXX: Should this be an error, or should we just abort this branch?
		return errors.New("no root certificate found")
	}

	// Serialize authority certificate for measurement
	var varData *bytes.Buffer
	switch mode {
	case FirmwareLoad:
		// Firmware measures the entire EFI_SIGNATURE_DATA, including the SignatureOwner
		varData = new(bytes.Buffer)
		if err := root.encode(varData); err != nil {
			return fmt.Errorf("cannot encode EFI_SIGNATURE_DATA for authority: %v", err)
		}
	case DirectLoadWithShimVerify:
		// Shim measures the certificate data, rather than the entire EFI_SIGNATURE_DATA
		varData = bytes.NewBuffer(root.data)
	}

	// Create event data, compute digest and perform extension for verification of this executable
	eventData := tcglog.EFIVariableEventData{
		VariableName: rootDb.variableName,
		UnicodeName:  rootDb.unicodeName,
		VariableData: varData.Bytes()}
	hash := hashAlgToGoHash(g.alg)
	if err := eventData.Encode(hash); err != nil {
		return fmt.Errorf("cannot encode EFI_VARIABLE_DATA: %v", err)
	}
	g.extendVerificationMeasurementIfUnique(hash.Sum(nil), mode)

	return nil
}

func readShimVendorCert(r io.ReaderAt) ([]byte, error) {
	pefile, err := pe.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("cannot decode PE binary: %v", err)
	}

	// Shim's vendor certificate is in the .vendor_cert section.
	section := pefile.Section(".vendor_cert")
	if section == nil {
		return nil, errors.New("missing .vendor_cert section")
	}

	// Shim's .vendor_cert section starts with a cert_table struct (see shim.c in the shim source)
	sectionReader := io.NewSectionReader(section, 0, (1<<63)-1)
	var certSize uint32
	if err := binary.Read(sectionReader, binary.LittleEndian, &certSize); err != nil {
		return nil, fmt.Errorf("cannot read vendor cert size: %v", err)
	}

	// A size of zero is valid
	if certSize == 0 {
		return nil, nil
	}

	if _, err := sectionReader.Seek(4, io.SeekCurrent); err != nil {
		return nil, fmt.Errorf("cannot seek ahead to read vendor cert offset: %v", err)
	}

	var certOffset uint32
	if err := binary.Read(sectionReader, binary.LittleEndian, &certOffset); err != nil {
		return nil, fmt.Errorf("cannot read vendor cert offset: %v", err)
	}

	certReader := io.NewSectionReader(section, int64(certOffset), int64(certSize))
	certData, err := ioutil.ReadAll(certReader)
	if err != nil {
		return nil, fmt.Errorf("cannot read vendor cert data: %v", err)
	}

	return certData, nil
}

func (g *secureBootPolicyGen) processShimExecutable(r io.ReaderAt, mode OSComponentLoadType,
	next []*OSComponent) error {
	// Compute and extend a measurement for verification of this shim executable
	if err := g.processPeBinaryVerification(r, mode); err != nil {
		return fmt.Errorf("cannot compute measurement for PE binary verification: %v", err)
	}

	// Ensure we start with an empty list of shim measurements
	g.enterShimScope()
	defer g.exitShimScope()

	// Enter a new secure boot DB set scope
	g.enterDbScope()
	defer g.exitDbScope()

	// Extract this shim's vendor cert and update the secure boot DB set
	vendorCert, err := readShimVendorCert(r)
	if err != nil {
		return fmt.Errorf("cannot extract vendor certificate from Shim: %v", err)
	}
	if vendorCert != nil {
		g.dbSet().shimDb = secureBootDb{variableName: shimGuid,
			unicodeName: shimName,
			signatures: []*efiSignatureData{
				&efiSignatureData{signatureType: efiCertX509Guid, data: vendorCert}}}
	}

	for i, component := range next {
		if component.LoadType != DirectLoadWithShimVerify {
			return fmt.Errorf("invalid load method for component loaded from shim at index %d", i)
		}
	}

	// Continue computing events
	if err := g.continueComputingOSLoadEvents(next); err != nil {
		return fmt.Errorf("cannot compute events for subsequent components: %v", err)
	}

	return nil
}

func (g *secureBootPolicyGen) processExecutable(r io.ReaderAt, mode OSComponentLoadType,
	next []*OSComponent) error {
	// Compute and extend a measurement for verification of this executable
	if err := g.processPeBinaryVerification(r, mode); err != nil {
		return fmt.Errorf("cannot compute measurement for PE binary verification: %v", err)
	}

	// Continue computing events
	if err := g.continueComputingOSLoadEvents(next); err != nil {
		return fmt.Errorf("cannot compute events for subsequent components: %v", err)
	}

	return nil
}

func isShimExecutable(r io.ReaderAt) (bool, error) {
	pefile, err := pe.NewFile(r)
	if err != nil {
		return false, fmt.Errorf("cannot decode PE binary: %v", err)
	}
	return pefile.Section(".vendor_cert") != nil, nil
}

func (g *secureBootPolicyGen) computeOSLoadEvents(component *OSComponent) error {
	b, err := component.Image.ReadAll()
	if err != nil {
		return fmt.Errorf("cannot read OS component: %v", err)
	}

	r := bytes.NewReader(b)
	if isShim, err := isShimExecutable(r); err != nil {
		return fmt.Errorf("cannot determine type of OS component: %v", err)
	} else if isShim {
		if err := g.processShimExecutable(r, component.LoadType, component.Next); err != nil {
			return fmt.Errorf("cannot process Shim executable: %v", err)
		}
	} else {
		if err := g.processExecutable(r, component.LoadType, component.Next); err != nil {
			return fmt.Errorf("cannot process executable: %v", err)
		}
	}

	return nil
}

func (g *secureBootPolicyGen) continueComputingOSLoadEvents(next []*OSComponent) error {
	if len(next) == 0 {
		digest := g.pcrStack[len(g.pcrStack)-1]
		for _, d := range g.outputDigests {
			if bytes.Equal(d, digest) {
				return nil
			}
		}
		g.outputDigests = append(g.outputDigests, digest)
		return nil
	}

	for i, component := range next {
		if err := func() error {
			g.enterMeasurementScope()
			defer g.exitMeasurementScope()
			return g.computeOSLoadEvents(component)
		}(); err != nil {
			return fmt.Errorf("cannot compute events for component at index %d: %v", i, err)
		}
	}

	return nil
}

func (g *secureBootPolicyGen) processEvents(events []classifiedEvent) error {
Loop:
	for i, event := range events {
		switch event.class {
		case eventClassUnclassified:
			g.extendMeasurement(tpm2.Digest(event.event.Event.Digests[tcglog.AlgorithmId(g.alg)]))
		case eventClassDb:
			// Handle current db
			path := dbPath
			if dbPathForTesting != "" {
				path = dbPathForTesting
			}

			var db []byte
			if f, err := os.Open(path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("cannot open db from efivarfs: %v", err)
			} else if f != nil {
				defer f.Close()
				d, err := ioutil.ReadAll(f)
				if err != nil {
					return fmt.Errorf("cannot read UEFI db from efivarfs: %v", err)
				}
				f.Close()
				db = d[4:]
			}
			if err := func() error {
				g.enterMeasurementScope()
				defer g.exitMeasurementScope()
				return g.processSecureBootDb(db, events[i+1:])
			}(); err != nil {
				return fmt.Errorf("cannot process db measurement event with current db "+
					"contents: %v", err)
			}
			// TODO: Handle db updates here
			break Loop
		case eventClassDbx:
			// Handle current dbx
			path := dbxPath
			if dbxPathForTesting != "" {
				path = dbxPathForTesting
			}

			var dbx []byte
			if f, err := os.Open(path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("cannot open dbx from efivarfs: %v", err)
			} else if f != nil {
				defer f.Close()
				d, err := ioutil.ReadAll(f)
				if err != nil {
					return fmt.Errorf("cannot read UEFI dbx from efivarfs: %v", err)
				}
				f.Close()
				dbx = d[4:]
			}
			if err := func() error {
				g.enterMeasurementScope()
				defer g.exitMeasurementScope()
				return g.processSecureBootDbx(dbx, events[i+1:])
			}(); err != nil {
				return fmt.Errorf("cannot process dbx measurement event with current dbx "+
					"contents: %v", err)
			}
			// TODO: Handle dbx updates here
			break Loop
		case eventClassDriverVerification:
			g.extendVerificationMeasurement(
				tpm2.Digest(event.event.Event.Digests[tcglog.AlgorithmId(g.alg)]), FirmwareLoad)
		case eventClassDriverAndInitialAppVerification:
			// The event corresponds to the verification of the initial EFI executable, but it's not
			// exclusive to that. Extend it now before proceding to ccompute the OS load events (and
			// if the initial OS verification event is the same then it will be filtered out anyway)
			g.extendVerificationMeasurement(
				tpm2.Digest(event.event.Event.Digests[tcglog.AlgorithmId(g.alg)]), FirmwareLoad)
			fallthrough
		case eventClassInitialAppVerification:
			if err := g.continueComputingOSLoadEvents(g.params.LoadPaths); err != nil {
				return fmt.Errorf("cannot compute OS load events: %v", err)
			}
			break Loop
		}
	}

	return nil
}

func (g *secureBootPolicyGen) run(secureBootEvents []classifiedEvent) (tpm2.DigestList, error) {
	g.enterDbScope()
	defer g.exitDbScope()

	// The MOK db is mirrored by Shim from a variable that's only accessible to boot services, to a variable
	// that's accessible at runtime. It also adds the vendor certificate to the mirrored variable. The problem
	// is that we can't distinguish whether a certificate is really a MOK or whether it was the vendor cert
	// for the Shim executable used during this boot, and we need to identify the source of a certificate as
	// that forms part of the measurement. For now, just don't support FDE when booting with components that
	// are signed with a MOK
	//if f, err := os.Open(mokListPath); err != nil && !os.IsNotExist(err) {
	//	return nil, fmt.Errorf("cannot open MokListRT from efivarfs: %v", err)
	//} else if f != nil {
	//	defer f.Close()
	//	mokList, err := ioutil.ReadAll(f)
	//	if err != nil {
	//		return nil, fmt.Errorf("cannot read MokListRT from efivarfs: %v", err)
	//	}
	//	f.Close()
	//	certs, err := decodeSecureBootDb(mokList[4:])
	//	if err != nil {
	//		return nil, fmt.Errorf("cannot decode MokListRT: %v", err)
	//	}
	//	g.contextStack.peek().mokDb =
	//		secureBootDb{variableName: shimGuid, unicodeName: mokListName, certs: certs}
	//}

	g.enterMeasurementScope()
	defer g.exitMeasurementScope()

	defer func() {
		g.outputDigests = nil
		if len(g.dbStack) != 1 {
			panic("mismatched number of enterDbScope / exitDbScope calls")
		}
		if len(g.pcrStack) != 1 || len(g.firmwareVerificationEvents) != 1 {
			panic("mismatched number of enterMeasurementScope / exitMeasurementScope calls")
		}
		if len(g.shimVerificationEvents) != 0 {
			panic("mismatched number of enterShimScope / exitShimScope calls")
		}
	}()

	if err := g.processEvents(secureBootEvents); err != nil {
		return nil, fmt.Errorf("cannot process events from event log: %v", err)
	}

	return g.outputDigests, nil
}

// computeSecureBootPolicyDigests takes a set of parameters detailing permitted secure boot sequences
// and the location of updates to db / dbx, and uses these in combination with a TCG event log to generate
// a set of secure boot PCR (#7) digests that can be used in a TPM authorization policy. It does this
// by replaying the event log, substituting the measurements of db and dbx with measurements computed from
// the current contents, and also the computed contents with the pending updates applied. Once it
// encounters the EV_EFI_VARIABLE_AUTHORITY event corresponding to the pre-OS to OS transition, it computes
// the sequence of EV_EFI_VARIABLE_AUTHORITY verification events for the specified permitted secure boot
// sequences by extracting the signing certificate from each component and using this to compute the
// measurement. Before returning, the list of computed digests is de-duplicated.
// For the most common case where boot components at each level in the tree are signed with the same
// key, each boot path has the same trust path, and there are no pending db / dbx updates - this is just
// a very complicated way of calculating a single digest value. Where it's really useful is when there are
// pending db / dbx updates or where a boot component in the tree is updated and the update is signed with
// a new key (and this function is called with both the old and new components present in params) - in
// which case this can compute multiple digests that can be used in an OR policy to allow updates to be
// applied atomically.
func computeSecureBootPolicyDigests(tpm *tpm2.TPMContext, alg tpm2.AlgorithmId, params *SealParams) (
	tpm2.DigestList, error) {
	logPath := eventLogPath
	if eventLogPathForTesting != "" {
		logPath = eventLogPathForTesting
	}

	// Load and replay event log
	log, err := tcglog.ReplayAndValidateLog(logPath, tcglog.LogOptions{})
	if err != nil {
		return nil, fmt.Errorf("cannot parse and validate event log: %v", err)
	}

	if !log.Algorithms.Contains(tcglog.AlgorithmId(alg)) {
		return nil, errors.New("event log does not have the requested algorithm")
	}

	// Determine if the log has secure boot policy events
	if _, exists := log.ExpectedPCRValues[tcglog.PCRIndex(secureBootPCR)]; !exists {
		return nil, errors.New("event log is missing secure boot policy events")
	}

	// Read the current value of PCR7 (secure boot policy) to make sure it is consistent with the log
	// TODO: Read this from the TPM during early boot and store the value somewhere, to allow other components
	// to measure to this PCR without breaking our ability to detect if the log is sane
	_, digests, err := tpm.PCRRead(tpm2.PCRSelectionList{
		tpm2.PCRSelection{Hash: alg, Select: []int{secureBootPCR}}})
	if err != nil {
		return nil, fmt.Errorf("cannot read current secure boot policy PCR value from TPM: %v", err)
	}
	digestFromLog := log.ExpectedPCRValues[tcglog.PCRIndex(secureBootPCR)][tcglog.AlgorithmId(alg)]
	if !bytes.Equal(digests[0], digestFromLog) {
		return nil, fmt.Errorf("secure boot policy PCR value is not consistent with the events from the "+
			"event log (TPM value: %x, value calculated from replaying log: %x)", digests[0],
			digestFromLog)
	}

	// First pass over the log to make sure things on the current boot are sane.
	for _, event := range log.ValidatedEvents {
		switch event.Event.PCRIndex {
		case bootManagerCodePCR:
			if event.Event.EventType == tcglog.EventTypeEFIAction &&
				event.Event.Data.String() == returningFromEfiApplicationEvent {
				// Firmware should record this event if an EFI application returns to the boot
				// manager. Bail out if this happened because the policy might not make sense.
				return nil, errors.New("the current boot was preceeded by a boot attempt to " +
					"another EFI application that returned to the boot manager without a " +
					"reboot in between")
			}
		case secureBootPCR:
			switch event.Event.EventType {
			case tcglog.EventTypeEFIVariableDriverConfig:
				efiVarData, isEfiVar := event.Event.Data.(*tcglog.EFIVariableEventData)
				if !isEfiVar {
					return nil, fmt.Errorf("%s secure boot policy event has invalid event "+
						"data", event.Event.EventType)
				}
				if efiVarData.VariableName == efiGlobalVariableGuid &&
					efiVarData.UnicodeName == sbStateName {
					switch {
					case event.Event.Index > 0:
						// The spec says that secure boot policy must be measured again if
						// the system supports changing it before ExitBootServices without
						// a reboot. But the policy we create won't make sense, so bail
						// out
						return nil, errors.New("secure boot policy was modified after " +
							"the initial secure boot configuration measurement " +
							"without performing a reboot")
					case efiVarData.VariableData[0] == 0x00:
						// This actually shouldn't happen - there's no event log when
						// secure boot is disabled on the devices I've tested on
						return nil, errors.New("the current boot was performed with " +
							"secure boot disabled in firmware")
					}
				}
			case tcglog.EventTypeSeparator:
			case tcglog.EventTypeEFIVariableAuthority:
				efiVarData, isEfiVar := event.Event.Data.(*tcglog.EFIVariableEventData)
				if !isEfiVar {
					return nil, fmt.Errorf("%s secure boot policy event has invalid event "+
						"data", event.Event.EventType)
				}
				if efiVarData.VariableName == shimGuid &&
					efiVarData.UnicodeName == mokSbStateName {
					// MokSBState is set to 0x01 if secure boot enforcement is disabled in
					// shim. The variable is deleted when secure boot enforcement is enabled,
					// so don't bother looking at the value here. It doesn't make a lot of
					// sense to create a policy if secure boot enforcement is disabled in shim
					return nil, errors.New("the current boot was performed with validation " +
						"disabled in Shim")
				}
			default:
				return nil, fmt.Errorf("unexpected secure boot policy event type: %s",
					event.Event.EventType)
			}
		}
	}

	// Classify secure boot policy events to identify the interesting ones.
	events, err := classifySecureBootEvents(log.ValidatedEvents)
	if err != nil {
		return nil, fmt.Errorf("cannot classify secure boot policy events from event log: %v", err)
	}

	// Pass over the classified secure boot policy events again and make sure the events that are interesting
	// have the expected digests. If the digests are unexpected, then that means the events were measured
	// in a way that we don't understand, and therefore we're unable to create a working policy.
	for _, event := range events {
		if event.class == eventClassUnclassified || event.class == eventClassDriverVerification {
			continue
		}

		if len(event.event.IncorrectDigestValues) != 0 {
			return nil, fmt.Errorf("digest for secure boot policy %s event at index %d is not "+
				"consistent with the associated event data", event.event.Event.EventType,
				event.event.Event.Index)
		}

		// Detect the problem fixed by https://github.com/rhboot/shim/pull/178 in shim
		if event.event.MeasuredTrailingBytes > 0 {
			return nil, fmt.Errorf("digest for secure boot policy %s event at index %d contains "+
				"trailing bytes", event.event.Event.EventType, event.event.Event.Index)
		}
	}

	gen := &secureBootPolicyGen{alg: alg, params: params}
	return gen.run(events)
}
