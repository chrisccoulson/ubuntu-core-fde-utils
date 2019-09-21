package fdeutil

import (
	"bytes"
	"crypto/sha256"
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

const (
	eventLogPath = "/sys/kernel/security/tpm0/binary_bios_measurements"
)

type eventClass int

const (
	eventClassUnclassified eventClass = iota
	eventClassDb
	eventClassDbx
	eventClassShim
	eventClassGrub
	eventClassKernel
)

const (
	dbName      string = "db"
	dbxName     string = "dbx"
	mokListName string = "MokList"
	shimName    string = "Shim"

	dbPath      string = "/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f"
	dbxPath     string = "/sys/firmware/efi/efivars/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f"
	mokListPath string = "/sys/firmware/efi/efivars/MokListRT-605dab50-e046-4300-abb6-3dd810dd8b23"

	winCertTypePKCSSignedData uint16 = 2
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

type verificationMode int

const (
	verificationModeFw verificationMode = iota
	verificationModeShim
)

type classifiedEvent struct {
	class eventClass
	event *tcglog.ValidatedEvent
}

func classifySecureBootEvents(events []*tcglog.ValidatedEvent) ([]classifiedEvent, error) {
	var out []classifiedEvent
	// Populate the list of classified events, by iterating forwards over the log and identifying the db and
	// dbx measurements in the process
	for _, e := range events {
		if e.Event.PCRIndex != secureBootPCR {
			continue
		}

		c := eventClassUnclassified
		if e.Event.EventType == tcglog.EventTypeEFIVariableDriverConfig {
			efiVarData, isEfiVar := e.Event.Data.(*tcglog.EFIVariableEventData)
			if !isEfiVar {
				return nil, fmt.Errorf("%s event type has invalid event data", e.Event.EventType)
			}
			switch efiVarData.VariableName {
			case efiGlobalVariableGuid:
				if efiVarData.UnicodeName == "SecureBoot" {
					switch {
					case len(out) > 0:
						// The spec says that secure boot policy must be measured again
						// if the system supports changing it before ExitBootServices
						// without a reboot. But the policy we create won't make sense, so
						// bail out
						return nil, errors.New("secure boot policy was modified after " +
							"the initial secure boot configuration measurement " +
							"without performing a reboot")
					case efiVarData.VariableData[0] == 0x00:
						// This actually shouldn't happen - there's no event log when
						// secure boot is disabled on the devices I've tested on
						return nil, errors.New("this boot was performed with secure "+
							"boot disabled in firmware")
					}
				}
			case efiImageSecurityDatabaseGuid:
				switch efiVarData.UnicodeName {
				case "db":
					c = eventClassDb
				case "dbx":
					c = eventClassDbx
				}
			}
		}
		out = append(out, classifiedEvent{class: c, event: e})
	}

	// Go backwards until the separator event, classifying the kernel, grub and shim verification measurements
	verifyEvents := []eventClass{eventClassShim, eventClassGrub, eventClassKernel}
	Loop:
	for i := len(out) - 1; i >= 0; i-- {
		if len(verifyEvents) == 0 {
			break
		}

		e := &out[i]
		switch e.event.Event.EventType {
		case tcglog.EventTypeSeparator:
			break Loop
		case tcglog.EventTypeEFIVariableAuthority:
			efiVarData, isEfiVar := out[i].event.Event.Data.(*tcglog.EFIVariableEventData)
			if !isEfiVar {
				return nil, fmt.Errorf("%s event type has invalid event data",
					e.event.Event.EventType)
			}
			if efiVarData.VariableName == shimGuid && efiVarData.UnicodeName == "MokSBState" {
				if efiVarData.VariableData[0] == 0x01 {
					// It doesn't make a lot of sense to create a policy if secure boot
					// enforcement is disabled in shim
					return nil, errors.New("this boot was performed with validation "+
						"disabled in Shim")
				}
				continue Loop
			}
			n := len(verifyEvents) - 1
			if n == 0 && (efiVarData.VariableName != efiImageSecurityDatabaseGuid ||
				efiVarData.UnicodeName != dbName) {
				return nil, errors.New("unexpected data for Shim verification event")
			}
			e.class = verifyEvents[n]
			verifyEvents = verifyEvents[:n]
		default:
			return nil, fmt.Errorf("unexpected event type %s logged after secure boot configuration",
				out[i].event.Event.EventType)
		}
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

func hashExtend(alg tpm2.AlgorithmId, dest, update tpm2.Digest) {
	h := hashAlgToGoHash(alg)
	h.Write(dest)
	h.Write(update)

	copy(dest, h.Sum(nil))
}

type efiCertificateDataX509 struct {
	owner tcglog.EFIGUID
	cert  *x509.Certificate
}

func (e *efiCertificateDataX509) encode(buf io.Writer) error {
	if err := e.owner.Encode(buf); err != nil {
		return fmt.Errorf("cannot encode EFI_GUID: %v", err)
	}
	if _, err := buf.Write(e.cert.Raw); err != nil {
		return fmt.Errorf("cannot write certificate: %v", err)
	}
	return nil
}

type secureBootDb struct {
	variableName tcglog.EFIGUID
	unicodeName string
	certs []*efiCertificateDataX509
}

type secureBootContext struct {
	uefiDb  secureBootDb
	mokDb secureBootDb
	shimDb secureBootDb
}

func (c *secureBootContext) copy() *secureBootContext {
	return &secureBootContext{uefiDb: c.uefiDb, mokDb: c.mokDb, shimDb: c.shimDb}
}

type secureBootContextStack []*secureBootContext

func (s *secureBootContextStack) peek() *secureBootContext {
	if len(*s) == 0 {
		return nil
	}
	return (*s)[len(*s)-1]
}

func (s *secureBootContextStack) push(c *secureBootContext) {
	*s = append(*s, c)
}

func (s *secureBootContextStack) pop() *secureBootContext {
	if len(*s) == 0 {
		return nil
	}
	n := len(*s) - 1
	c := (*s)[n]
	*s = (*s)[:n]
	return c
}

func decodeSecureBootDb(data []byte) ([]*efiCertificateDataX509, error) {
	var out []*efiCertificateDataX509

	r := bytes.NewReader(data)

	for {
		start := r.Len()

		signatureType, err := decodeEFIGUID(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("cannot decode SignatureType from EFI_SIGNATURE_LIST: %v", err)
		}

		var signatureListSize uint32
		if err := binary.Read(r, binary.LittleEndian, &signatureListSize); err != nil {
			return nil, fmt.Errorf("cannot read SignatureListSize from EFI_SIGNATURE_LIST: %v", err)
		}

		if *signatureType != efiCertX509Guid {
			if _, err := r.Seek(int64(signatureListSize)+int64(r.Len())-int64(start),
				io.SeekCurrent); err != nil {
				return nil, fmt.Errorf("cannot seek to next EFI_SIGNATURE_LIST: %v", err)
			}
		}

		var signatureHeaderSize uint32
		if err := binary.Read(r, binary.LittleEndian, &signatureHeaderSize); err != nil {
			return nil, fmt.Errorf("cannot read SignatureHeaderSize from EFI_SIGNATURE_LIST: %v", err)
		}

		var signatureSize uint32
		if err := binary.Read(r, binary.LittleEndian, &signatureSize); err != nil {
			return nil, fmt.Errorf("cannot read SignatureSize from EFI_SIGNATURE_LIST: %v", err)
		}

		if _, err := r.Seek(int64(signatureHeaderSize), io.SeekCurrent); err != nil {
			return nil, fmt.Errorf("cannot seek to array of signatures within "+
				"EFI_SIGNATURE_LIST: %v", err)
		}

		numOfSignatures := (signatureListSize - signatureHeaderSize) / signatureSize
		for i := uint32(0); i < numOfSignatures; i++ {
			start := r.Len()

			signatureOwner, err := decodeEFIGUID(r)
			if err != nil {
				return nil, fmt.Errorf("cannot decode SignatureOwner from EFI_SIGNATURE_DATA: %v",
					err)
			}

			data := make([]byte, int64(signatureSize)+int64(r.Len())-int64(start))
			if _, err := io.ReadFull(r, data); err != nil {
				return nil, fmt.Errorf("cannot obtain EFI_SIGNATURE_DATA contents: %v", err)
			}

			cert, err := x509.ParseCertificate(data)
			if err != nil {
				return nil, fmt.Errorf("cannot decode X509 certificate from EFI_SIGNATURE_DATA: "+
					"%v", err)
			}

			out = append(out, &efiCertificateDataX509{owner: *signatureOwner, cert: cert})
		}
	}

	return out, nil
}

type digestStack []tpm2.Digest

func (l *digestStack) peek() tpm2.Digest {
	if len(*l) == 0 {
		return nil
	}
	return (*l)[len(*l)-1]
}

func (l *digestStack) push(d tpm2.Digest) {
	*l = append(*l, d)
}

func (l *digestStack) pop() tpm2.Digest {
	if len(*l) == 0 {
		return nil
	}
	n := len(*l) - 1
	d := (*l)[n]
	*l = (*l)[:n]
	return d
}

type secureBootPolicyGen struct {
	input *PolicyInputData

	contextStack secureBootContextStack
	pcrStack     digestStack

	digests tpm2.DigestList
}

func (g *secureBootPolicyGen) processSecureBootDb(db []byte, secureBootEvents []classifiedEvent) error {
	// Push a copy of the current secure boot PCR digest on to the stack
	currentDigest := g.pcrStack.peek()
	g.pcrStack.push(make(tpm2.Digest, len(currentDigest)))
	copy(g.pcrStack.peek(), currentDigest)
	defer g.pcrStack.pop()

	// Compute and extend a measurement for this db
	data := tcglog.EFIVariableEventData{
		VariableName: efiImageSecurityDatabaseGuid,
		UnicodeName:  dbName,
		VariableData: db}
	hash := sha256.New()
	if err := data.Encode(hash); err != nil {
		return fmt.Errorf("cannot encode EFI_VARIABLE_DATA: %v", err)
	}
	hashExtend(defaultHashAlgorithm, g.pcrStack.peek(), hash.Sum(nil))

	// Push a copy of the current secure boot context on to the stack
	g.contextStack.push(g.contextStack.peek().copy())
	defer g.contextStack.pop()

	// Decode this db and update the secure boot context
	certs, err := decodeSecureBootDb(db)
	if err != nil {
		return fmt.Errorf("cannot decode secure boot db: %v", err)
	}
	g.contextStack.peek().uefiDb =
		secureBootDb{variableName: efiImageSecurityDatabaseGuid, unicodeName: dbName, certs: certs}

	// Continue replaying events
	if err := g.processEvents(secureBootEvents); err != nil {
		return fmt.Errorf("cannot process subsequent events from event log: %v", err)
	}

	return nil
}

func (g *secureBootPolicyGen) processSecureBootDbx(dbx []byte, secureBootEvents []classifiedEvent) error {
	// Push a copy of the current secure boot PCR digest on to the stack
	current := g.pcrStack.peek()
	g.pcrStack.push(make(tpm2.Digest, len(current)))
	copy(g.pcrStack.peek(), current)
	defer g.pcrStack.pop()

	// Compute and extend a measurement for this dbx
	data := tcglog.EFIVariableEventData{
		VariableName: efiImageSecurityDatabaseGuid,
		UnicodeName:  dbxName,
		VariableData: dbx}
	hash := sha256.New()
	if err := data.Encode(hash); err != nil {
		return fmt.Errorf("cannot encode EFI_VARIABLE_DATA: %v", err)
	}
	hashExtend(defaultHashAlgorithm, g.pcrStack.peek(), hash.Sum(nil))

	// Continue replaying events
	if err := g.processEvents(secureBootEvents); err != nil {
		return fmt.Errorf("cannot process subsequent events from event log: %v", err)
	}

	return nil
}

func (g *secureBootPolicyGen) processPeBinaryVerification(r io.ReaderAt, mode verificationMode) error {
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

	// Grab the certificate of the signing authority
	signer := p7.GetOnlySigner()
	if signer == nil {
		return errors.New("cannot obtain signer certificate from signature")
	}

	// Look for the issuing authority in the UEFI db, and if the verifier is shim, also look in MOK db and
	// at shim's vendor cert
	dbs := []*secureBootDb{&g.contextStack.peek().uefiDb}
	if mode == verificationModeShim {
		dbs = append(dbs, &g.contextStack.peek().mokDb, &g.contextStack.peek().shimDb)
	}

	var root *efiCertificateDataX509
	var rootDb *secureBootDb
	Outer:
	for _, db := range dbs {
		for _, c := range db.certs {
			if bytes.Equal(c.cert.Raw, signer.Raw) {
				// The signing certificate is actually the root in the DB
				root = c
				rootDb = db
				break Outer
			}
			if err := signer.CheckSignatureFrom(c.cert); err == nil {
				// The signing certificate was issued by this root
				root = c
				rootDb = db
				break Outer
			}
		}
	}

	if root == nil {
		// XXX: Should this be an error, or should we just abort this branch?
		return errors.New("cannot compute measurement: no root certificate found")
	}

	// Serialize authority certificate for measurement
	var varData *bytes.Buffer
	switch mode {
	case verificationModeFw:
		// Firmware measures the entire EFI_SIGNATURE_DATA, including the SignatureOwner
		varData = new(bytes.Buffer)
		if err := root.encode(varData); err != nil {
			return fmt.Errorf("cannot encode EFI_SIGNATURE_DATA for authority: %v", err)
		}
	case verificationModeShim:
		// Shim measures the certificate data, rather than the entire EFI_SIGNATURE_DATA
		varData = bytes.NewBuffer(root.cert.Raw)
	}

	// Create event data, compute digest and perform extension for verification of this executable
	eventData := tcglog.EFIVariableEventData{
		VariableName: rootDb.variableName,
		UnicodeName:  rootDb.unicodeName,
		VariableData: varData.Bytes()}
	hash := sha256.New()
	if err := eventData.Encode(hash); err != nil {
		return fmt.Errorf("cannot encode EFI_VARIABLE_DATA: %v", err)
	}
	hashExtend(defaultHashAlgorithm, g.pcrStack.peek(), hash.Sum(nil))

	return nil
}

func (g *secureBootPolicyGen) processShimExecutable(r io.ReaderAt, secureBootEvents []classifiedEvent) error {
	// Push a copy of the current secure boot PCR digest on to the stack
	current := g.pcrStack.peek()
	g.pcrStack.push(make(tpm2.Digest, len(current)))
	copy(g.pcrStack.peek(), current)
	defer g.pcrStack.pop()

	// Compute and extend a measurement for verification of this shim executable
	if err := g.processPeBinaryVerification(r, verificationModeFw); err != nil {
		return fmt.Errorf("cannot compute measurement for PE binary verification: %v", err)
	}

	// Push a copy of the current secure boot context on to the stack
	g.contextStack.push(g.contextStack.peek().copy())
	defer g.contextStack.pop()

	// Extract this shim's vendor cert and update the secure boot context
	pefile, err := pe.NewFile(r)
	if err != nil {
		return fmt.Errorf("cannot decode PE binary: %v", err)
	}

	// Shim's vendor certificate is in the .vendor_cert section. This section starts with a cert_table struct
	// (see shim.c in the shim source)
	section := pefile.Section(".vendor_cert")
	if section == nil {
		return errors.New("missing .vendor_cert section")
	}
	sectionReader := io.NewSectionReader(section, 0, (1<<63)-1)
	var certSize uint32
	if err := binary.Read(sectionReader, binary.LittleEndian, &certSize); err != nil {
		return fmt.Errorf("cannot read vendor cert size: %v", err)
	}
	if _, err := sectionReader.Seek(4, io.SeekCurrent); err != nil {
		return fmt.Errorf("cannot seek ahead to read vendor cert offset: %v", err)
	}
	var certOffset uint32
	if err := binary.Read(sectionReader, binary.LittleEndian, &certOffset); err != nil {
		return fmt.Errorf("cannot read vendor cert offset: %v", err)
	}

	certReader := io.NewSectionReader(section, int64(certOffset), int64(certSize))
	certData, err := ioutil.ReadAll(certReader)
	if err != nil {
		return fmt.Errorf("cannot read vendor cert data: %v", err)
	}
	vendorCert, err := x509.ParseCertificate(certData)
	if err != nil {
		return fmt.Errorf("cannot decode vendor cert: %v", err)
	}
	g.contextStack.peek().shimDb = secureBootDb{variableName: shimGuid,
		unicodeName: shimName,
		certs: []*efiCertificateDataX509{&efiCertificateDataX509{cert: vendorCert}}}

	// Continue replaying events
	if err := g.processEvents(secureBootEvents); err != nil {
		return fmt.Errorf("cannot process subsequent events from event log: %v", err)
	}

	return nil
}

func (g *secureBootPolicyGen) processExecutable(r io.ReaderAt, excessBytes []byte,
	secureBootEvents []classifiedEvent) error {
	if len(excessBytes) > 0 {
		// Old versions of shim measured additional zero bytes due to a padding error. Whilst we mirror
		// that behaviour when generating digests, also generate digests using the correct behaviour that
		// will work with newer versions of shim. 
		if err := g.processExecutable(r, nil, secureBootEvents); err != nil {
			return err
		}
	}

	// Push a copy of the current secure boot PCR digest on to the stack
	current := g.pcrStack.peek()
	g.pcrStack.push(make(tpm2.Digest, len(current)))
	copy(g.pcrStack.peek(), current)
	defer g.pcrStack.pop()

	// Compute and extend a measurement for verification of this executable
	if err := g.processPeBinaryVerification(r, verificationModeShim); err != nil {
		return fmt.Errorf("cannot compute measurement for PE binary verification: %v", err)
	}

	// Continue replaying events
	if err := g.processEvents(secureBootEvents); err != nil {
		return fmt.Errorf("cannot process subsequent events from event log: %v", err)
	}

	return nil
}

func (g *secureBootPolicyGen) processEvents(secureBootEvents []classifiedEvent) error {
	for i, event := range secureBootEvents {
		switch event.class {
		case eventClassUnclassified:
			hashExtend(defaultHashAlgorithm, g.pcrStack.peek(),
				tpm2.Digest(event.event.Event.Digests[tcglog.AlgorithmId(defaultHashAlgorithm)]))
		case eventClassDb:
			// Handle current db
			var db []byte
			if f, err := os.Open(dbPath); err != nil && !os.IsNotExist(err) {
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
			if err := g.processSecureBootDb(db, secureBootEvents[i+1:]); err != nil {
				return fmt.Errorf("cannot process db measurement event with current db contents: "+
					"%v", err)
			}
			// TODO: Handle db update here
			return nil
		case eventClassDbx:
			// Handle current dbx
			var dbx []byte
			if f, err := os.Open(dbxPath); err != nil && !os.IsNotExist(err) {
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
			if err := g.processSecureBootDbx(dbx, secureBootEvents[i+1:]); err != nil {
				return fmt.Errorf("cannot process dbx measurement event with current dbx "+
					"contents: %v", err)
			}
			// TODO: Handle dbx update here
			return nil
		case eventClassShim:
			if len(g.input.ShimExecutables) == 0 {
				return errors.New("no shim executables provided")
			}
			for j, shim := range g.input.ShimExecutables {
				b, err := shim.GetBytes()
				if err != nil {
					return fmt.Errorf("cannot read shim executable at index %d: %v", j, err)
				}
				r := bytes.NewReader(b)
				if err := g.processShimExecutable(r, secureBootEvents[i+1:]); err != nil {
					return fmt.Errorf("cannot process shim executable at index %d: %v", j, err)
				}
			}
			return nil
		case eventClassGrub:
			if len(g.input.GrubExecutables) == 0 {
				return errors.New("no GRUB executables provided")
			}
			for j, grub := range g.input.GrubExecutables {
				b, err := grub.GetBytes()
				if err != nil {
					return fmt.Errorf("cannot read GRUB executable at index %d: %v", j, err)
				}
				r := bytes.NewReader(b)
				if err := g.processExecutable(r, event.event.ExcessMeasuredBytes,
					secureBootEvents[i+1:]); err != nil {
					return fmt.Errorf("cannot process GRUB executable at index %d: %v", j, err)
				}
			}
			return nil
		case eventClassKernel:
			if len(g.input.Kernels) == 0 {
				return errors.New("no kernel images provided")
			}
			for j, kernel := range g.input.Kernels {
				b, err := kernel.GetBytes()
				if err != nil {
					return fmt.Errorf("cannot read kernel at index %d: %v", j, err)
				}
				r := bytes.NewReader(b)
				if err := g.processExecutable(r, event.event.ExcessMeasuredBytes,
					secureBootEvents[i+1:]); err != nil {
					return fmt.Errorf("cannot process kernel at index %d: %v", j, err)
				}
			}
			return nil
		}
	}

	g.digests = append(g.digests, g.pcrStack.peek())

	return nil
}

func (g *secureBootPolicyGen) run(secureBootEvents []classifiedEvent) (tpm2.DigestList, error) {
	g.contextStack.push(&secureBootContext{})
	defer g.contextStack.pop()

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

	g.pcrStack.push(make(tpm2.Digest, getDigestSize(defaultHashAlgorithm)))
	defer g.pcrStack.pop()

	defer func() {
		g.digests = nil
	}()

	if err := g.processEvents(secureBootEvents); err != nil {
		return nil, fmt.Errorf("cannot process events from event log: %v", err)
	}

	var out tpm2.DigestList
	Loop:
	for _, digest := range g.digests {
		for _, o := range out {
			if bytes.Equal(o, digest) {
				continue Loop
			}
		}
		out = append(out, digest)
	}

	return out, nil
}

func computeSecureBootPolicyDigests(tpm *tpm2.TPMContext, data *PolicyInputData) (tpm2.DigestList, error) {
	log, err := tcglog.ReplayAndValidateLog(eventLogPath, tcglog.LogOptions{})
	if err != nil {
		return nil, fmt.Errorf("cannot parse and validate event log: %v", err)
	}
	if _, exists := log.LogPCRValues[tcglog.PCRIndex(secureBootPCR)]; !exists {
		return nil, errors.New("event log is missing secure boot policy events")
	}
	// TODO: Read this from the TPM during early boot and store the value somewhere, to allow other components
	// to measure to this PCR without breaking our ability to detect if the log is sane
	_, digests, err := tpm.PCRRead(tpm2.PCRSelectionList{
		tpm2.PCRSelection{Hash: defaultHashAlgorithm, Select: []int{secureBootPCR}}})
	if err != nil {
		return nil, fmt.Errorf("cannot read current secure boot policy PCR value from TPM: %v", err)
	}
	if !bytes.Equal(digests[0],
		log.LogPCRValues[tcglog.PCRIndex(secureBootPCR)][tcglog.AlgorithmId(defaultHashAlgorithm)]) {
		return nil, errors.New("secure boot policy PCR value is not consistent with the events from the "+
			"event log")
	}

	events, err := classifySecureBootEvents(log.ValidatedEvents)
	if err != nil {
		return nil, fmt.Errorf("cannot classify secure boot policy events from event log: %v", err)
	}
	for _, event := range events {
		if event.class == eventClassUnclassified {
			continue
		}
		if len(event.event.UnexpectedDigestValues) != 0 {
			return nil, errors.New("digest for secure boot policy event is not consistent with the "+
				"associated event data")
		}
	}

	gen := &secureBootPolicyGen{input: data}
	return gen.run(events)
}
