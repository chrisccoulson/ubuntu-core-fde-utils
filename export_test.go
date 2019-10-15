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
)

func NewKeydata() *keyData {
	// XXX: mock this so that its actually useful and can be marshalled
	return &keyData{
		KeyPrivate:        []byte("key-private"),
		KeyPublic:         &tpm2.Public{},
		KeyCreationData:   &tpm2.CreationData{},
		KeyCreationTicket: &tpm2.TkCreation{},
	}
}

func (k *keyData) WriteToFile(dest string) error {
	return k.writeToFile(dest)
}
