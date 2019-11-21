// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package fdeutil

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"time"

	"github.com/chrisccoulson/go-tpm2"
	"github.com/intel-go/cpuid"
	"github.com/snapcore/snapd/httputil"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/osutil/sys"

	"golang.org/x/xerrors"
)

const (
	tpmPath string = "/dev/tpm0"

	ekCertHandle tpm2.Handle = 0x01c00002

	sanDirectoryNameTag = 4
)

var (
	oidExtensionSubjectAltName     = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidTcgAttributeTpmManufacturer = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	oidTcgAttributeTpmModel        = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	oidTcgAttributeTpmVersion      = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
	oidTcgKpEkCertificate          = asn1.ObjectIdentifier{2, 23, 133, 8, 1}
)

type TPMDeviceAttributes struct {
	Manufacturer    tpm2.TPMManufacturer
	Model           string
	FirmwareVersion uint32
}

// TPMConnection corresponds to a connection to a TPM device, and is a wrapper around *tpm2.TPMContext.
type TPMConnection struct {
	*tpm2.TPMContext
	verifiedEkCertChain      []*x509.Certificate
	verifiedDeviceAttributes *TPMDeviceAttributes
	ekContext                tpm2.ResourceContext
	hmacSession              tpm2.ResourceContext
}

// VerifiedEkCertChain returns the verified certificate chain for the endorsement key certificate obtained from this TPM. It was
// verified using one of the built-in TPM manufacturer root CA certificates.
func (t *TPMConnection) VerifiedEkCertChain() []*x509.Certificate {
	return t.verifiedEkCertChain
}

// VeririedDeviceAttributes returns the TPM device attributes for this TPM, obtained from the verified endorsement key certificate.
func (t *TPMConnection) VerifiedDeviceAttributes() *TPMDeviceAttributes {
	return t.verifiedDeviceAttributes
}

// EkContext returns a reference to the TPM's persistent endorsement key, if one exists. If the endorsement key certificate has been
// verified, the returned ResourceContext will correspond to the object for which the certificate was issued and can safely be used
// to share secrets with the TPM.
func (t *TPMConnection) EkContext() (tpm2.ResourceContext, error) {
	if t.ekContext == nil {
		return nil, ErrProvisioning
	}
	return t.ekContext, nil
}

// HmacSession returns a HMAC session instance which was created in order to conduct a proof-of-ownership check of the private part
// of the endorsement key on the TPM. It is retained in order to reduce the number of sessions that need to be created during unseal
// operations, and is created with a symmetric algorithm so that it is suitable for parameter encryption.
func (t *TPMConnection) HmacSession() *tpm2.Session {
	if t.hmacSession == nil {
		return nil
	}
	return &tpm2.Session{Context: t.hmacSession, Attrs: tpm2.AttrContinueSession}
}

func (t *TPMConnection) Close() error {
	t.FlushContext(t.hmacSession)
	return t.TPMContext.Close()
}

type invalidEkError struct{}

func (e invalidEkError) Error() string {
	return "object is not a valid endorsement key"
}

func (t *TPMConnection) createTransientEkContext(endorsementAuth []byte) (tpm2.ResourceContext, error) {
	endorsement, _ := t.WrapHandle(tpm2.HandleEndorsement)
	sessionContext, err := t.StartAuthSession(nil, endorsement, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256, endorsementAuth)
	if err != nil {
		return nil, xerrors.Errorf("cannot start auth session: %w", err)
	}
	defer t.FlushContext(sessionContext)

	context, _, _, _, _, _, err :=
		t.CreatePrimary(tpm2.HandleEndorsement, nil, &ekTemplate, nil, nil, &tpm2.Session{Context: sessionContext})
	return context, err
}

// verifyEkContext verifies that the public area of the ResourceContext that was read back from the TPM is associated with the
// supplied EK certificate. It does this by obtaining the public key from the EK certificate, inserting it in to the standard EK
// template, computing the expected name of the EK object and then verifying that this name matches the result of
// ResourceContext.Name. This works because go-tpm2 cross-checks that the name and public area returned from TPM2_ReadPublic match
// when initializing the ResourceContext.
//
// Success confirms that the ResourceContext references the public area associated with the public key of the supplied EK certificate.
// If that certificate has been verified, the ResourceContext can safely be used to encrypt secrets that can only be decrpyted and
// used by the TPM for which the EK certificate was issued, eg, for salting an authorization session that is then used for parameter
// encryption.
func verifyEkContext(cert *x509.Certificate, context tpm2.ResourceContext) error {
	// Obtain the RSA public key from the endorsement certificate
	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("cannot obtain RSA public key from certificate")
	}

	// Insert the RSA public key in to the EK template to compute the name of the EK object we expected to read back from the TPM.
	var ekPublic *tpm2.Public
	b, _ := tpm2.MarshalToBytes(ekTemplate)
	tpm2.UnmarshalFromBytes(b, &ekPublic)

	if pubKey.E != 65537 {
		ekPublic.Params.RSADetail().Exponent = uint32(pubKey.E)
	}
	ekPublic.Unique.Data = tpm2.PublicKeyRSA(pubKey.N.Bytes())

	expectedEkName, err := ekPublic.Name()
	if err != nil {
		panic(fmt.Sprintf("cannot compute expected name of EK object: %v", err))
	}

	// Verify that the public area associated with context corresponds to the object that the endorsement certificate was issued for.
	// We do this by comparing the name read back from the TPM with the one we computed from the EK template with the certificate's
	// public key inserted in to it (remember that go-tpm2 has already verified that the name that was read back is consistent with the
	// public area).
	if !bytes.Equal(context.Name(), expectedEkName) {
		// An exponent of 0 in the public area corresponds to the default (65537) exponent, but some TPM's don't return 0 in the
		// public area (my Nuvoton TPM, for example). If the initial name comparison with exponent == 0 failed, try exponent == 65537.
		ekPublic.Params.RSADetail().Exponent = uint32(pubKey.E)
		expectedEkName, err := ekPublic.Name()
		if err != nil {
			panic(fmt.Sprintf("cannot compute expected name of EK object: %v", err))
		}
		if !bytes.Equal(context.Name(), expectedEkName) {
			return errors.New("public area doesn't match certificate")
		}
	}

	return nil
}

type verificationError struct {
	err error
}

func (e verificationError) Error() string {
	return e.err.Error()
}

func (t *TPMConnection) init(endorsementAuth []byte) error {
	// Allow init to be called more than once by flushing the previous session
	if t.hmacSession != nil && t.hmacSession.Handle() != tpm2.HandleUnassigned {
		if err := t.FlushContext(t.hmacSession); err != nil {
			return xerrors.Errorf("cannot flush existing HMAC session: %w", err)
		}
	}

	// Acquire an unverified ResourceContext for the EK. If there is no object at the persistent EK index, then attempt to create
	// a transient EK with the supplied authorization.
	//
	// Under the hood, go-tpm2 initializes the ResourceContext with TPM2_ReadPublic (or TPM2_CreatePrimary if we create a new one),
	// and it cross-checks that the returned name and public area match. The returned name is available via ekContext.Name and the
	// returned public area is retained by ekContext and used to share secrets with the TPM.
	//
	// Without verification against the EK certificate, ekContext isn't yet safe to use for secret sharing with the TPM.
	ekContext, err := func() (tpm2.ResourceContext, error) {
		rc, err := t.WrapHandle(ekHandle)
		if err == nil {
			return rc, nil
		}
		if _, unavail := err.(tpm2.ResourceUnavailableError); !unavail {
			return nil, err
		}
		if rc, err := t.createTransientEkContext(endorsementAuth); err == nil {
			return rc, nil
		}
		return nil, err
	}()

	if ekContext.Handle().Type() == tpm2.HandleTypeTransient {
		defer t.FlushContext(ekContext)
	}

	if len(t.verifiedEkCertChain) > 0 {
		// Verify that ekContext is associated with the verified EK certificate. If the first attempt fails and ekContext references a
		// persistent object, then try to create a transient EK with the provided authorization and make another attempt at verification,
		// in case the persistent object isn't a valid EK.
		rc, err := func() (tpm2.ResourceContext, error) {
			err := verifyEkContext(t.verifiedEkCertChain[0], ekContext)
			if err == nil {
				return ekContext, nil
			}
			if ekContext.Handle().Type() == tpm2.HandleTypeTransient {
				return nil, err
			}
			transientEkContext, err2 := t.createTransientEkContext(endorsementAuth)
			if err2 != nil {
				return nil, err
			}
			err = verifyEkContext(t.verifiedEkCertChain[0], transientEkContext)
			if err == nil {
				return transientEkContext, nil
			}
			return nil, err
		}()
		if err != nil {
			return verificationError{xerrors.Errorf("cannot verify public area of endorsement key read from the TPM: %w", err)}
		}
		if ekContext.Handle().Type() == tpm2.HandleTypePersistent && rc.Handle().Type() == tpm2.HandleTypeTransient {
			// We created and verified a transient EK
			defer t.FlushContext(rc)
		}
		ekContext = rc
	} else if ekContext.Handle().Type() == tpm2.HandleTypePersistent {
		// If we don't have a verified EK certificate and ekContext is a persistent object, just do a sanity check that the public area
		// returned from the TPM has the expected properties. If it doesn't, then attempt to create a transient EK with the provided
		// authorization value.
		if ok, err := isObjectPrimaryKeyWithTemplate(t.TPMContext, tpm2.HandleEndorsement, ekContext, &ekTemplate, nil); err != nil {
			return xerrors.Errorf("cannot determine if object is a primary key in the endorsement hierarchy: %w", err)
		} else if !ok {
			rc, err := t.createTransientEkContext(endorsementAuth)
			if err != nil {
				return verificationError{errors.New("public area of endorsement key read from the TPM is invalid")}
			}
			defer t.FlushContext(rc)
			ekContext = rc
		}
	}

	// Verify that the TPM we're connected to is the one that the endorsement certificate was issued for (if we've validated it) by
	// creating a session that's salted with a value protected by the public part of the endorsement key, using that to integrity protect
	// a command and verifying we get a valid response. The salt (and therefore the session key) can only be recovered on and used by the
	// TPM for which the endorsement certificate was issued, so a correct response means we're communicating with that TPM.
	symmetric := tpm2.SymDef{
		Algorithm: tpm2.SymAlgorithmAES,
		KeyBits:   tpm2.SymKeyBitsU{Data: uint16(128)},
		Mode:      tpm2.SymModeU{Data: tpm2.SymModeCFB}}
	sessionContext, err := t.StartAuthSession(ekContext, nil, tpm2.SessionTypeHMAC, &symmetric, defaultHashAlgorithm, nil)
	if err != nil {
		return xerrors.Errorf("cannot create HMAC session: %w", err)
	}
	succeeded := false
	defer func() {
		if succeeded {
			return
		}
		t.FlushContext(sessionContext)
	}()

	if len(t.verifiedEkCertChain) > 0 {
		session := tpm2.Session{Context: sessionContext, Attrs: tpm2.AttrContinueSession | tpm2.AttrAudit}
		_, err = t.GetRandom(20, &session)
		if err != nil {
			if isAuthFailError(err) {
				return verificationError{errors.New("endorsement key proof of ownership check failed")}
			}
			return xerrors.Errorf("cannot execute command to complete EK proof of ownership check: %w", err)
		}
	}

	succeeded = true

	if ekContext.Handle().Type() == tpm2.HandleTypePersistent {
		t.ekContext = ekContext
	}
	t.hmacSession = sessionContext
	return nil
}

func readEkCert(tpm *tpm2.TPMContext) (*x509.Certificate, error) {
	ekCertIndex, err := tpm.WrapHandle(ekCertHandle)
	if err != nil {
		return nil, xerrors.Errorf("cannot create context: %w", err)
	}

	ekCertPub, _, err := tpm.NVReadPublic(ekCertIndex)
	if err != nil {
		return nil, xerrors.Errorf("cannot read public area of index: %w", err)
	}

	data, err := tpm.NVRead(ekCertIndex, ekCertIndex, ekCertPub.Size, 0, nil)
	if err != nil {
		return nil, xerrors.Errorf("cannot read index: %w", err)
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, xerrors.Errorf("cannot parse cert: %w", err)
	}

	return cert, nil
}

func fetchIntermediates(cert *x509.Certificate) ([]*x509.Certificate, error) {
	if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return nil, nil
	}

	client := httputil.NewHTTPClient(&httputil.ClientOptions{Timeout: 10 * time.Second})
	var out []*x509.Certificate

	for {
		if len(cert.IssuingCertificateURL) == 0 {
			if cpuid.HasFeature(cpuid.HYPERVISOR) {
				break
			}
			return nil, fmt.Errorf("cannot download certificate for issuer of %v: no issuer URLs", cert.Subject)
		}

		var parent *x509.Certificate
		var err error
		for _, issuerUrl := range cert.IssuingCertificateURL {
			if p, e := func(url string) (*x509.Certificate, error) {
				resp, err := client.Get(url)
				if err != nil {
					return nil, xerrors.Errorf("GET request failed: %w", err)
				}
				body, err := ioutil.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					return nil, xerrors.Errorf("cannot read body: %w", err)
				}
				cert, err := x509.ParseCertificate(body)
				if err != nil {
					return nil, xerrors.Errorf("cannot parse certificate: %w", err)
				}
				return cert, nil
			}(issuerUrl); e == nil {
				parent = p
				err = nil
				break
			} else {
				err = xerrors.Errorf("download from %s failed: %w", issuerUrl, e)
			}
		}

		if err != nil {
			return nil, xerrors.Errorf("cannot download certificate for issuer of %v: %w", cert.Subject, err)
		}

		if bytes.Equal(parent.RawIssuer, parent.RawSubject) {
			break
		}

		out = append(out, parent)
		cert = parent
	}

	return out, nil
}

var openDefaultTcti = func() (io.ReadWriteCloser, error) {
	return tpm2.OpenTPMDevice(tpmPath)
}

func connectToDefaultTPM() (*tpm2.TPMContext, error) {
	tcti, err := openDefaultTcti()
	if err != nil {
		return nil, xerrors.Errorf("cannot open TPM device: %w", err)
	}

	tpm, _ := tpm2.NewTPMContext(tcti)
	return tpm, nil
}

func checkChainForEkCertUsage(chain []*x509.Certificate) bool {
	if len(chain) == 0 {
		return false
	}

NextCert:
	for i := len(chain) - 1; i >= 0; i-- {
		cert := chain[i]
		if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
			continue
		}

		for _, usage := range cert.ExtKeyUsage {
			if usage == x509.ExtKeyUsageAny {
				continue NextCert
			}
		}

		for _, usage := range cert.UnknownExtKeyUsage {
			if usage.Equal(oidTcgKpEkCertificate) {
				continue NextCert
			}
		}

		return false
	}

	return true
}

func parseTPMDeviceAttributesFromDirectoryName(dirName pkix.RDNSequence) (*TPMDeviceAttributes, pkix.RDNSequence, error) {
	var attrs TPMDeviceAttributes
	var rdnsOut pkix.RelativeDistinguishedNameSET

	hasManufacturer, hasModel, hasVersion := false, false, false

	for _, rdns := range dirName {
		for _, atv := range rdns {
			switch {
			case atv.Type.Equal(oidTcgAttributeTpmManufacturer):
				if hasManufacturer {
					return nil, nil, asn1.StructuralError{Msg: "duplicate TPM manufacturer"}
				}
				hasManufacturer = true
				s, ok := atv.Value.(string)
				if !ok {
					return nil, nil, asn1.StructuralError{Msg: "invalid TPM attribute value"}
				}
				if !strings.HasPrefix(s, "id:") {
					return nil, nil, asn1.StructuralError{Msg: "invalid TPM manufacturer"}
				}
				hex, err := hex.DecodeString(strings.TrimPrefix(s, "id:"))
				if err != nil {
					return nil, nil, asn1.StructuralError{Msg: fmt.Sprintf("invalid TPM manufacturer: %v", err)}
				}
				if len(hex) != 4 {
					return nil, nil, asn1.StructuralError{Msg: "invalid TPM manufacturer: too short"}
				}
				attrs.Manufacturer = tpm2.TPMManufacturer(binary.BigEndian.Uint32(hex))
			case atv.Type.Equal(oidTcgAttributeTpmModel):
				if hasModel {
					return nil, nil, asn1.StructuralError{Msg: "duplicate TPM model"}
				}
				hasModel = true
				s, ok := atv.Value.(string)
				if !ok {
					return nil, nil, asn1.StructuralError{Msg: "invalid TPM attribute value"}
				}
				attrs.Model = s
			case atv.Type.Equal(oidTcgAttributeTpmVersion):
				if hasVersion {
					return nil, nil, asn1.StructuralError{Msg: "duplicate TPM firmware version"}
				}
				hasVersion = true
				s, ok := atv.Value.(string)
				if !ok {
					return nil, nil, asn1.StructuralError{Msg: "invalid TPM attribute value"}
				}
				if !strings.HasPrefix(s, "id:") {
					return nil, nil, asn1.StructuralError{Msg: "invalid TPM firmware version"}
				}
				hex, err := hex.DecodeString(strings.TrimPrefix(s, "id:"))
				if err != nil {
					return nil, nil, asn1.StructuralError{Msg: fmt.Sprintf("invalid TPM firmware version: %v", err)}
				}
				b := make([]byte, 4)
				copy(b[len(b)-len(hex):], hex)
				attrs.FirmwareVersion = binary.BigEndian.Uint32(b)
			default:
				continue
			}
			rdnsOut = append(rdnsOut, atv)
		}
	}

	if hasManufacturer && hasModel && hasVersion {
		return &attrs, pkix.RDNSequence{rdnsOut}, nil
	}
	return nil, nil, errors.New("incomplete or missing attributes")
}

func parseTPMDeviceAttributesFromSAN(data []byte) (*TPMDeviceAttributes, pkix.RDNSequence, error) {
	var seq asn1.RawValue
	if rest, err := asn1.Unmarshal(data, &seq); err != nil {
		return nil, nil, err
	} else if len(rest) > 0 {
		return nil, nil, errors.New("trailing bytes after SAN extension")
	}
	if !seq.IsCompound || seq.Tag != asn1.TagSequence || seq.Class != asn1.ClassUniversal {
		return nil, nil, asn1.StructuralError{Msg: "invalid SAN sequence"}
	}

	rest := seq.Bytes
	for len(rest) > 0 {
		var err error
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return nil, nil, err
		}

		if v.Class != asn1.ClassContextSpecific {
			return nil, nil, asn1.StructuralError{Msg: "invalid SAN entry"}
		}

		if v.Tag == sanDirectoryNameTag {
			var dirName pkix.RDNSequence
			if rest, err := asn1.Unmarshal(v.Bytes, &dirName); err != nil {
				return nil, nil, err
			} else if len(rest) > 0 {
				return nil, nil, errors.New("trailing bytes after SAN extension directory name")
			}

			return parseTPMDeviceAttributesFromDirectoryName(dirName)
		}
	}

	return nil, nil, errors.New("no directoryName")
}

type certDataError struct {
	err error
}

func (e certDataError) Error() string {
	return e.err.Error()
}

type ekCertData struct {
	Cert              []byte
	IntermediateCerts [][]byte
}

// verifyEkCertificate verifies the provided certificate and intermediate certificates against the built-in roots, and verifies
// that the certificate is a valid EK certificate, according to the "TCG EK Credential Profile" specification.
//
// On success, it returns a verified certificate chain. This function will also return success if there is no certificate and
// it is executed inside a guest VM, in order to support fallback to a non-secure connection when using swtpm in a guest VM.
func verifyEkCertificate(ekCertReader io.Reader) ([]*x509.Certificate, *TPMDeviceAttributes, error) {
	// Load EK cert and intermediates
	var data ekCertData
	if err := tpm2.UnmarshalFromReader(ekCertReader, &data); err != nil {
		return nil, nil, certDataError{xerrors.Errorf("cannot unmarshal: %w", err)}
	}

	cert, err := x509.ParseCertificate(data.Cert)
	if err != nil {
		return nil, nil, certDataError{xerrors.Errorf("cannot parse endorsement key certificate: %w", err)}
	}

	intermediates := x509.NewCertPool()
	for _, d := range data.IntermediateCerts {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return nil, nil, certDataError{xerrors.Errorf("cannot parse intermediate certificates: %w", err)}
		}
		intermediates.AddCert(c)
	}

	// Parse the built-in roots
	roots := x509.NewCertPool()
	for _, data := range rootCAs {
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			panic(fmt.Sprintf("cannot parse root CA: %v", err))
		}
		roots.AddCert(cert)
	}

	if cert.PublicKeyAlgorithm != x509.RSA {
		return nil, nil, verificationError{errors.New("certificate contains a public key with the wrong algorithm")}
	}

	// MUST have valid basic constraints with CA=FALSE
	if cert.IsCA || !cert.BasicConstraintsValid {
		return nil, nil, verificationError{errors.New("certificate contains invalid basic constraints")}
	}

	var attrs *TPMDeviceAttributes
	for _, e := range cert.Extensions {
		if e.Id.Equal(oidExtensionSubjectAltName) {
			// SubjectAltName MUST be critical if subject is empty
			if len(cert.Subject.Names) == 0 && !e.Critical {
				return nil, nil, verificationError{errors.New("certificate with empty subject contains non-critical SAN extension")}
			}
			var err error
			var attrsRDN pkix.RDNSequence
			attrs, attrsRDN, err = parseTPMDeviceAttributesFromSAN(e.Value)
			// SubjectAltName MUST include TPM manufacturer, model and firmware version
			if err != nil {
				return nil, nil, verificationError{xerrors.Errorf("cannot parse TPM device attributes: %w", err)}
			}
			if len(cert.Subject.Names) == 0 {
				// If subject is empty, fill the Subject field with the TPM device attributes so that String() returns something useful
				cert.Subject.FillFromRDNSequence(&attrsRDN)
				cert.Subject.ExtraNames = cert.Subject.Names
			}
			break
		}
	}

	// SubjectAltName MUST exist. If it does exist but doesn't contain the correct TPM device attributes, we would have returned earlier.
	if attrs == nil {
		return nil, nil, verificationError{errors.New("certificate has no SAN extension")}
	}

	// If SAN contains only fields unhandled by crypto/x509 and it is marked as critical, then it ends up here. Remove it because
	// we've handled it ourselves and x509.Certificate.Verify fails if we leave it here.
	for i, e := range cert.UnhandledCriticalExtensions {
		if e.Equal(oidExtensionSubjectAltName) {
			copy(cert.UnhandledCriticalExtensions[i:], cert.UnhandledCriticalExtensions[i+1:])
			cert.UnhandledCriticalExtensions = cert.UnhandledCriticalExtensions[:len(cert.UnhandledCriticalExtensions)-1]
			break
		}
	}

	// Key Usage MUST contain keyEncipherment
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		return nil, nil, verificationError{errors.New("certificate has incorrect key usage")}
	}

	// Verify EK certificate for any usage - we've already verified that the leaf has the correct usage.
	opts := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	candidates, err := cert.Verify(opts)
	if err != nil {
		// Allow a fallback when running in a hypervisor in order to support swtpm
		if cpuid.HasFeature(cpuid.HYPERVISOR) {
			candidates = make([][]*x509.Certificate, 1)
			candidates[0] = make([]*x509.Certificate, 1)
			candidates[0][0] = cert
		} else {
			return nil, nil, verificationError{xerrors.Errorf("certificate verification failed: %w", err)}
		}
	}

	// Extended Key Usage MUST contain tcg-kp-EKCertificate (and also require that the usage is nested)
	var chain []*x509.Certificate
	for _, c := range candidates {
		if checkChainForEkCertUsage(c) {
			chain = c
			break
		}
	}

	if chain == nil {
		return nil, nil, verificationError{errors.New("no certificate chain has the correct extended key usage")}
	}

	// At this point, we've verified that the endorsent certificate has the correct properties and was issued by a trusted TPM
	// manufacturer, and is therefore a valid assertion by that manufacturer that the contained public key is associated with a
	// properly formed endorsement key with the expected properties (restricted, non-duplicable decrypt key), generated from a
	// private seed injected in to a genuine TPM by them. Secrets encrypted by this public key can only be decrypted by and used
	// on the TPM for which this certificate was issued.

	return chain, attrs, nil
}

func fetchEkCertificate(tpm *TPMConnection, w io.Writer) error {
	var data ekCertData

	if cert, err := readEkCert(tpm.TPMContext); err != nil {
		var unavailErr tpm2.ResourceUnavailableError
		if !xerrors.As(err, &unavailErr) {
			return xerrors.Errorf("cannot obtain endorsement certificate from TPM: %w", err)
		}
	} else {
		data.Cert = cert.Raw

		intermediates, err := fetchIntermediates(cert)
		if err != nil {
			return xerrors.Errorf("cannot obtain intermediate certificates for %s: %w", cert.Subject, err)
		}

		data.IntermediateCerts = make([][]byte, 0, len(intermediates))
		for _, c := range intermediates {
			data.IntermediateCerts = append(data.IntermediateCerts, c.Raw)
		}
	}

	if err := tpm2.MarshalToWriter(w, &data); err != nil {
		return xerrors.Errorf("cannot marshal cert data: %w", err)
	}

	return nil
}

// FetchAndSaveEkCertificate attempts to obtain the endorsement key certificate for the TPM assocated with the tpm parameter, and
// then download the associated intermediate certificates.
//
// On success, the EK certificate and its intermediates are saved atomically to the file referenced by dest in a form that can be read
// by SecureConnectToDefaultTPM. If no EK certificate can be obtained, this function will return an error unless executed inside a
// guest VM. In this case, an empty certificate that can be unmarshalled correctly by SecureConnectToDefaultTPM will be written in
// order to support fallback to a non-secure connection when connecting to swtpm inside a guest VM.
func FetchAndSaveEkCertificate(tpm *TPMConnection, dest string) error {
	f, err := osutil.NewAtomicFile(dest, 0600, 0, sys.UserID(osutil.NoChown), sys.GroupID(osutil.NoChown))
	if err != nil {
		return xerrors.Errorf("cannot create new atomic file: %w", err)
	}
	defer f.Cancel()

	if err := fetchEkCertificate(tpm, f); err != nil {
		return err
	}

	if err := f.Commit(); err != nil {
		return xerrors.Errorf("cannot atomically replace file: %w", err)
	}

	return nil
}

// ConnectToDefaultTPM will attempt to connect to the default TPM. It makes no attempt to verify the authenticity of the TPM. This
// function is useful for connecting to a device that isn't correctly provisioned and for which the endorsement hierarchy
// authorization value is unknown (so that it can be cleared), or for connecting to a device in order to execute
// FetchAndSaveEkCertificate. It should not be used in any other scenario.
func ConnectToDefaultTPM() (*TPMConnection, error) {
	tpm, err := connectToDefaultTPM()
	if err != nil {
		return nil, err
	}

	t := &TPMConnection{TPMContext: tpm}

	succeeded := false
	defer func() {
		if succeeded {
			return
		}
		t.Close()
	}()

	if err := t.init(nil); err != nil {
		var ieErr invalidEkError
		var unavailErr tpm2.ResourceUnavailableError
		var verifyErr verificationError
		if !xerrors.As(err, &ieErr) && !xerrors.As(err, &unavailErr) && !xerrors.As(err, &verifyErr) {
			return nil, xerrors.Errorf("cannot initialize TPM connection: %w", err)
		}
	}

	succeeded = true
	return t, nil
}

// SecureConnectToDefaultTPM will attempt to connect to the default TPM, verify the manufacturer issued endorsement certificate
// against the built-in CA roots and then verify that the TPM is the one for which the endorsement certificate was issued. If
// provided, the ekCertReader argument should read from a file created previously by FetchAndSaveEkCertificate. This makes it
// possible to connect to the TPM without requiring network access to download certificates.
//
// If the data read from ekCertReader cannot be unmarshalled or parsed correctly, a InvalidEkCertError error will be returned.
//
// If ekCertReader is nil, this function will attempt to obtain the endorsement key certificate for the TPM and then download the
// required intermediate certificates. This requires network access. If network access is unavailable and there is no existing
// EK certificate blob created previously by FetchAndSaveEkCertificate, then ConnectToDefaultTPM must be used instead.
//
// If verification of the endorsement key certificate fails, a EkCertVerificationError error will be returned.
//
// In order for the TPM to prove it is the device for which the endorsement key certificate was issued, an endorsement key is
// required. If the TPM doesn't contain a valid persistent endorsement key at the expected location (eg, if ProvisionTPM hasn't been
// executed yet), this function will attempt to create a transient endorsement key. This requires knowledge of the endorsement
// hierarchy authorization value, which will be empty on a newly cleared device. If there is no object at the persistent endorsement
// key index and creation of a transient endorement key fails, ErrProvisioning will be returned.
//
// If the TPM cannot prove it is the device for which the endorsement key certificate was issued, a TPMVerificationError error will be
// returned. This can happen if there is an object at the persistent endorsement key index but it is not the object for which the
// endorsement key certificate was issued, and creation of a transient endorsement key fails because the correct endorsement hierarchy
// authorization value hasn't been provided.
func SecureConnectToDefaultTPM(ekCertReader io.Reader, endorsementAuth []byte) (*TPMConnection, error) {
	tpm, err := connectToDefaultTPM()
	if err != nil {
		return nil, err
	}

	succeeded := false
	defer func() {
		if succeeded {
			return
		}
		tpm.Close()
	}()

	t := &TPMConnection{TPMContext: tpm}

	if ekCertReader == nil {
		b := new(bytes.Buffer)
		if err := fetchEkCertificate(t, b); err != nil {
			return nil, EkCertVerificationError{err.Error()}
		}
		ekCertReader = b
	}

	chain, attrs, err := verifyEkCertificate(ekCertReader)
	if err != nil {
		var cdErr certDataError
		if xerrors.As(err, &cdErr) {
			return nil, InvalidEkCertError{err.Error()}
		}
		var verifyErr verificationError
		if xerrors.As(err, &verifyErr) {
			return nil, EkCertVerificationError{err.Error()}
		}
		return nil, xerrors.Errorf("cannot verify EK certificate: %w", err)
	}

	t.verifiedEkCertChain = chain
	t.verifiedDeviceAttributes = attrs

	if err := t.init(endorsementAuth); err != nil {
		var unavailErr tpm2.ResourceUnavailableError
		var ieErr invalidEkError
		if xerrors.As(err, &unavailErr) || xerrors.As(err, &ieErr) {
			return nil, ErrProvisioning
		}
		var verifyErr verificationError
		if xerrors.As(err, &verifyErr) {
			return nil, TPMVerificationError{err.Error()}
		}
		return nil, xerrors.Errorf("cannot initialize TPM connection: %w", err)
	}

	succeeded = true
	return t, nil
}
