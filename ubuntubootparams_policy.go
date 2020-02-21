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

	"github.com/chrisccoulson/go-tpm2"
	"github.com/chrisccoulson/tcglog-parser"

	"golang.org/x/xerrors"
)

func computeUbuntuBootParamsDigests(alg tpm2.HashAlgorithmId, params *PolicyParams) (tpm2.DigestList, error) {
	var out tpm2.DigestList
	for _, str := range params.KernelCommandlines {
		event := &tcglog.SystemdEFIStubEventData{Str: str}
		var buf bytes.Buffer
		if err := event.EncodeMeasuredBytes(&buf); err != nil {
			return nil, xerrors.Errorf("cannot encode kernel commandline event: %w", err)
		}

		h := alg.NewHash()
		buf.WriteTo(h)

		p := newSimulatedPCR(alg)
		p.extend(h.Sum(nil))

		out = append(out, p.value)
	}

	return out, nil
}
