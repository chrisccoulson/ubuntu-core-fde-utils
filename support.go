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
	"errors"
	"fmt"
	"os"

	"github.com/chrisccoulson/go-tpm2"
	"github.com/chrisccoulson/tcglog-parser"
)

// CheckSupport performs some checks to determine if the system is suitable for full disk encryption using this module. If no issues
// are found, then no error will be returned. If an error is returned, the system is not suitable for full disk encryption using
// this module, and the error will detail why.
func CheckSupport() error {
	tpm, err := ConnectToDefaultTPM()
	if err != nil {
		if os.IsNotExist(err) {
			return errors.New("no TPM device is available")
		}
		return fmt.Errorf("cannot connect to a TPM device: %v", err)
	}

	props, err := tpm.GetCapabilityTPMProperties(tpm2.PropertyPSFamilyIndicator, 1)
	if err != nil {
		if _, isTpm1Err := err.(tpm2.TPM1Error); isTpm1Err {
			return errors.New("a TPM1 device was detected")
		}
		return fmt.Errorf("cannot retrieve properties from TPM: %v", err)
	}
	if props[0].Value != 1 {
		// The platform spec details a set of minimum requirements, including algorithms
		// and commands that are mandatory. With this, we can avoid doing feature checking
		// (eg, we know that SHA-1 and SHA-256 are mandatory algorithms, and we know other
		// things like the NV counter support is mandatory).
		return errors.New("a TPM device is available but not compliant with the PC Client TPM Specification")
	}

	log, err := tcglog.ReplayAndValidateLog(eventLogPath, tcglog.LogOptions{})
	if err != nil {
		if os.IsNotExist(err) {
			return errors.New("no TCG event log is available")
		}
		return fmt.Errorf("encountered an error whilst validating the TCG event log: %v", err)
	}

	if !log.Algorithms.Contains(tcglog.AlgorithmId(defaultHashAlgorithm)) {
		return errors.New("the TCG event log does not contain events with the required digest algorithm")
	}

	_, digests, err := tpm.PCRRead(tpm2.PCRSelectionList{tpm2.PCRSelection{Hash: defaultHashAlgorithm, Select: []int{secureBootPCR}}})
	if err != nil {
		return fmt.Errorf("cannot read current secure boot policy PCR value from TPM: %v", err)
	}
	digestFromLog := log.ExpectedPCRValues[tcglog.PCRIndex(secureBootPCR)][tcglog.AlgorithmId(defaultHashAlgorithm)]
	if !bytes.Equal(digests[0], digestFromLog) {
		return errors.New("the current value of the secure boot PCR is not consistent with the events recorded in the TCG event log")
	}

	events, err := classifySecureBootEvents(log.ValidatedEvents)
	if err != nil {
		return fmt.Errorf("cannot classify secure boot policy events from TCG event log: %v", err)
	}

	for _, event := range events {
		if event.class == eventClassUnclassified || event.class == eventClassDriverVerification {
			continue
		}

		if len(event.event.IncorrectDigestValues) != 0 {
			return fmt.Errorf("the TCG event log contains a secure boot policy %s event at index %d with a digest that is not consistent "+
				"with the recorded event data", event.event.Event.EventType, event.event.Event.Index)
		}

		// Detect the problem fixed by https://github.com/rhboot/shim/pull/178 in shim
		if event.event.MeasuredTrailingBytes > 0 {
			return fmt.Errorf("the TCG event log contains a secure boot policy %s event at index %d with a digest that includes trailing "+
				"bytes", event.event.Event.EventType, event.event.Event.Index)
		}
	}

	return nil
}
