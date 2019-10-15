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

package fdeutil_test

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/chrisccoulson/ubuntu-core-fde-utils"
)

func TestInitCheckV1(t *testing.T) { TestingT(t) }

type keydataSuite struct{}

var _ = Suite(&keydataSuite{})

func (s *keydataSuite) TestWriteFileUnhappy(c *C) {
	kd := fdeutil.NewKeydata()
	kd.AskForPinHint = true

	dest := filepath.Join(c.MkDir(), "keydata")
	err := kd.WriteToFile(dest)
	c.Assert(err, ErrorMatches, "cannot marshal key data .*")

	_, err = ioutil.ReadFile(dest)
	c.Check(err, ErrorMatches, "open .*/keydata: no such file or directory")
}

// XXX: write a tests where something is marshalled
