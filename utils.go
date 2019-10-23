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
	"github.com/chrisccoulson/go-tpm2"

	"golang.org/x/xerrors"
)

func isAuthFailError(err error) bool {
	var sessionErr tpm2.TPMSessionError
	if !xerrors.As(err, &sessionErr) {
		return false
	}
	switch sessionErr.Code {
	case tpm2.ErrorAuthFail: // With DA implications
		return true
	case tpm2.ErrorBadAuth: // Without DA implications
		return true
	}
	return false
}
