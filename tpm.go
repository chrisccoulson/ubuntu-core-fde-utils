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
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
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
)

var (
	oidSubjectAlternativeName = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidTCGEkCertificate       = asn1.ObjectIdentifier{2, 23, 133, 8, 1}
)

// TPMConnection corresponds to a connection to a TPM device, and is a wrapper around *tpm2.TPMContext.
type TPMConnection struct {
	*tpm2.TPMContext
	verifiedEkCertChain []*x509.Certificate
	ekContext           tpm2.ResourceContext
	hmacSession         tpm2.ResourceContext
}

// VerifiedEkCertChain returns the verified endorsement certificate chain for the endorsement certificate obtained from
// this TPM. It was verified using one of the built-in TPM manufacturer root CAs
func (t *TPMConnection) VerifiedEkCertChain() []*x509.Certificate {
	return t.verifiedEkCertChain
}

// EkContext returns a reference to the TPM's endorsement key, if one exists. If the endorsement certificate has been verified,
// the returned ResourceContext will correspond to the key for which the certificate was issued.
func (t *TPMConnection) EkContext() (tpm2.ResourceContext, error) {
	if t.ekContext == nil || t.ekContext.Handle() == tpm2.HandleUnassigned {
		return nil, ErrProvisioning
	}
	return t.ekContext, nil
}

// HmacSession returns a HMAC session instance which was created to verify that the TPM contains the sensitive area of the endorsement
// key (accessible from TPMConnection.EkContext), and is therefore the TPM for which the endorsement certificate was issued. It is
// retained in order to reduce the number of sessions that need to be created during unseal operations, and is created with a
// symmetric algorithm for parameter encryption.
func (t *TPMConnection) HmacSession() (*tpm2.Session, error) {
	if t.hmacSession == nil || t.hmacSession.Handle() == tpm2.HandleUnassigned {
		return nil, ErrProvisioning
	}
	return &tpm2.Session{Context: t.hmacSession, Attrs: tpm2.AttrContinueSession}, nil
}

func (t *TPMConnection) Close() error {
	t.FlushContext(t.hmacSession)
	return t.TPMContext.Close()
}

type invalidEkError struct{}

func (e invalidEkError) Error() string {
	return "object is not a valid endorsement key"
}

// acquireEkContext returns a ResourceContext for the object resident in the endorsement key's slot on the TPM. Under the hood,
// go-tpm2 initializes the ResourceContext with TPM2_ReadPublic, and cross-checks that the returned name and public area match. The
// returned name is available via ResourceContext.Name and the returned public area is retained by the ResourceContext and used to
// share secrets with the TPM.
//
// If the TPM isn't provisioned yet, it attempt to create a transient EK using the provided authorization.
//
// Without verification against the EK certificate The returned ResourceContext isn't yet safe for secret sharing with the TPM.
func (t *TPMConnection) acquireEkContext(endorsementAuth []byte) (tpm2.ResourceContext, error) {
	createTransient := func() (tpm2.ResourceContext, error) {
		endorsement, _ := t.WrapHandle(tpm2.HandleEndorsement)
		sessionContext, err := t.StartAuthSession(nil, endorsement, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256, endorsementAuth)
		if err != nil {
			return nil, err
		}
		defer t.FlushContext(sessionContext)

		context, _, _, _, _, _, err :=
			t.CreatePrimary(tpm2.HandleEndorsement, nil, &ekTemplate, nil, nil, &tpm2.Session{Context: sessionContext})
		return context, err
	}

	ekContext, err := t.WrapHandle(ekHandle)
	if err != nil {
		if _, unavail := err.(tpm2.ResourceUnavailableError); unavail {
			if rc, err := createTransient(); err == nil {
				return rc, nil
			}
		}
		return nil, err
	}

	if ok, err := isObjectPrimaryKeyWithTemplate(t.TPMContext, tpm2.HandleEndorsement, ekContext, &ekTemplate, nil); err != nil {
		return nil, xerrors.Errorf("cannot determine if object is a primary key in the endorsement hierarchy: %w", err)
	} else if !ok {
		if rc, err := createTransient(); err == nil {
			return rc, nil
		}
		return nil, invalidEkError{}
	}

	return ekContext, nil
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

	// Acquire a ResourceContext for the EK
	ekContext, err := t.acquireEkContext(endorsementAuth)
	if err != nil {
		return xerrors.Errorf("cannot obtain context for endorsement key: %w", err)
	}

	if ekContext.Handle().Type() == tpm2.HandleTypeTransient {
		defer t.FlushContext(ekContext)
	}

	if len(t.verifiedEkCertChain) > 0 {
		// Verify that the ResourceContext is associated with the verified EK certificate
		if err := verifyEkContext(t.verifiedEkCertChain[0], ekContext); err != nil {
			return verificationError{xerrors.Errorf("cannot verify public area of endorsement key read from the TPM: %w", err)}
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
			if usage.Equal(oidTCGEkCertificate) {
				continue NextCert
			}
		}

		return false
	}

	return true
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

type certFileError struct {
	err error
}

func (e certFileError) Error() string {
	return e.err.Error()
}

type ekCertData struct {
	Cert              []byte
	IntermediateCerts [][]byte
}

// verifyEkCertificate verifies the provided certificate and intermediate certificates against the built-in roots, and verifies
// that the certificate is a valid EK certificate.
//
// On success, it returns a verified certificate chain. This function will also return success if there is no certificate and
// it is executed inside a guest VM, in order to support fallback to a non-secure connection when using swtpm in a guest VM.
func verifyEkCertificate(ekCertReader io.Reader) ([]*x509.Certificate, error) {
	// Load EK cert and intermediates
	var data ekCertData
	if err := tpm2.UnmarshalFromReader(ekCertReader, &data); err != nil {
		return nil, certFileError{xerrors.Errorf("cannot unmarshal: %w", err)}
	}

	// Allow a fallback when running in a hypervisor in order to support swtpm
	if len(data.Cert) == 0 && cpuid.HasFeature(cpuid.HYPERVISOR) {
		return nil, nil
	}

	cert, err := x509.ParseCertificate(data.Cert)
	if err != nil {
		return nil, certFileError{xerrors.Errorf("cannot parse endorsement key certificate: %w", err)}
	}

	intermediates := x509.NewCertPool()
	for _, d := range data.IntermediateCerts {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return nil, certFileError{xerrors.Errorf("cannot parse intermediate certificates: %w", err)}
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

	// If SAN contains only unhandled fields, it ends up here. Remove it and handle it ourselves below
	// TODO: Parse the SAN data
	for i, e := range cert.UnhandledCriticalExtensions {
		if e.Equal(oidSubjectAlternativeName) {
			copy(cert.UnhandledCriticalExtensions[i:], cert.UnhandledCriticalExtensions[i+1:])
			cert.UnhandledCriticalExtensions = cert.UnhandledCriticalExtensions[:len(cert.UnhandledCriticalExtensions)-1]
			break
		}
	}

	if cert.PublicKeyAlgorithm != x509.RSA {
		return nil, verificationError{errors.New("certificate contains a public key with the wrong algorithm")}
	}

	// Verify EK certificate for any usage
	opts := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	candidates, err := cert.Verify(opts)
	if err != nil {
		return nil, verificationError{xerrors.Errorf("certificate verification failed: %w", err)}
	}

	// Make sure we have a chain that permits the tcg-kg-EKCertificate extended key usage
	var chain []*x509.Certificate
	for _, c := range candidates {
		if checkChainForEkCertUsage(c) {
			chain = c
			break
		}
	}

	if chain == nil {
		return nil, verificationError{errors.New("certificate does not have the correct usage properties")}
	}

	// At this point, we've verified that the endorsent certificate has the correct properties and was issued by a trusted TPM
	// manufacturer, and is therefore a valid assertion by that manufacturer that the contained public key is associated with a
	// properly formed endorsement key with the expected properties (restricted, non-duplicable decrypt key), generated from a
	// private seed injected in to a genuine TPM by them. Secrets encrypted by this public key can only be decrypted by and used
	// on the TPM for which this certificate was issued.

	return chain, nil
}

// FetchEkCertificate attempts to obtain the endorsement key certificate for the TPM assocated with the tpm parameter, and then
// download the associated intermediate certificates.
//
// On success, the EK certificate and its intermediates are written to the provided io.Writer in a form that can be read by
// SecureConnectToDefaultTPM. If no EK certificate can be obtained, this function will return an error unless executed inside a guest
// VM. In this case, an empty certificate that can be unmarshalled correctly by SecureConnectoToDefaultTPM will be written in order to
// support fallback to a non-secure connection when connecting to swtpm inside a guest VM.
func FetchEkCertificate(tpm *TPMConnection, w io.Writer) error {
	var data ekCertData

	if cert, err := readEkCert(tpm.TPMContext); err != nil {
		var unavailErr tpm2.ResourceUnavailableError
		// Allow a fallback when running in a hypervisor in order to support swtpm. In this case, a missing EK cert is not an error,
		// and we write a file that unmarshals correctly (albeit, with no contents)
		if !xerrors.As(err, &unavailErr) || !cpuid.HasFeature(cpuid.HYPERVISOR) {
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
// guest VM. In this case, an empty certificate that can be unmarshalled correctly by SecureConnectoToDefaultTPM will be written in
// order to support fallback to a non-secure connection when connecting to swtpm inside a guest VM.
func FetchAndSaveEkCertificate(tpm *TPMConnection, dest string) error {
	f, err := osutil.NewAtomicFile(dest, 0600, 0, sys.UserID(osutil.NoChown), sys.GroupID(osutil.NoChown))
	if err != nil {
		return xerrors.Errorf("cannot create new atomic file: %w", err)
	}
	defer f.Cancel()

	if err := FetchEkCertificate(tpm, f); err != nil {
		return err
	}

	if err := f.Commit(); err != nil {
		return xerrors.Errorf("cannot atomically replace file: %w", err)
	}

	return nil
}

// ConnectToDefaultTPM will attempt to connect to the default TPM. It makes no attempt to verify the authenticity of the TPM. This
// function is useful for connecting to a device that isn't correctly provisioned and for which the endorsement hierarchy
// authorization value is unknown, or for connecting to a device in order to execute FetchAndSaveEkCertificate. It should not be
// used in any other scenario.
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

// SecureConnectToDefaultTPM will attempt to connect to the default TPM, verify the provided manufacturer issued endorsement
// certificate against the built-in CA roots and then verify that the TPM is the one for which the endorsement certificate was
// issued. The ekCertReader argument should read from a file created previously by FetchAndSaveEkCertificate.
//
// If the data read from ekCertReader cannot be unmarshalled or parsed correctly, a InvalidEkCertFileError error will be returned.
//
// If verification of the endorsement key certificate fails, a TPMVerificationError error will be returned.
//
// If the TPM cannot prove it is the device for which the endorsement key certificate was issued, a TPMVerificationError error will be
// returned.
//
// In order for the TPM to prove it is the device for which the endorsement key certificate was issued, an endorsement key is
// required. If the TPM doesn't contain a persistent endorsement key at the expected location (eg, if ProvisionTPM hasn't been
// executed yet), this function will attempt to create a transient endorsement key. This requires knowledge of the endorsement
// hierarchy authorization value, which will be empty on a newly cleared device. If this fails, ErrProvisioning will be returned.
func SecureConnectToDefaultTPM(ekCertReader io.Reader, endorsementAuth []byte) (*TPMConnection, error) {
	if ekCertReader == nil {
		return nil, errors.New("nil ekCertReader")
	}

	chain, err := verifyEkCertificate(ekCertReader)
	if err != nil {
		var cfErr certFileError
		if xerrors.As(err, &cfErr) {
			return nil, InvalidEkCertFileError{err.Error()}
		}
		var verifyErr verificationError
		if xerrors.As(err, &verifyErr) {
			return nil, TPMVerificationError{fmt.Sprintf("cannot verify endorsement key certificate: %v", err)}
		}
		return nil, xerrors.Errorf("cannot verify EK certificate: %w", err)
	}

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

	t := &TPMConnection{TPMContext: tpm, verifiedEkCertChain: chain}

	if err := t.init(endorsementAuth); err != nil {
		var unavailErr tpm2.ResourceUnavailableError
		var ieErr invalidEkError
		if xerrors.As(err, &unavailErr) || xerrors.As(err, &ieErr) {
			return nil, ErrProvisioning
		}
		var verifyErr verificationError
		if xerrors.As(err, &verifyErr) {
			return nil, TPMVerificationError{fmt.Sprintf("cannot initialize TPM connection: %v", err)}
		}
		return nil, xerrors.Errorf("cannot initialize TPM connection: %w", err)
	}

	succeeded = true
	return t, nil
}
