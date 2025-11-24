// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
)

func ReadUvarint(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, errors.New("data is empty")
	}
	r := bytes.NewReader(data)
	val, err := ReadUvarintReader(r)
	if err != nil {
		return 0, 0, err
	}
	return val, len(data) - r.Len(), nil
}

func ReadUvarintReader(r io.Reader) (uint64, error) {
	var ret uint64
	prefix := make([]byte, 1)
	if _, err := io.ReadFull(r, prefix); err != nil {
		return 0, err
	}
	switch prefix[0] {
	case 0xff:
		data := make([]byte, 8)
		if _, err := io.ReadFull(r, data); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return 0, errors.New("invalid length for uint64")
			}
			return 0, err
		}
		ret = uint64(binary.LittleEndian.Uint64(data))
		return ret, nil
	case 0xfe:
		data := make([]byte, 4)
		if _, err := io.ReadFull(r, data); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return 0, errors.New("invalid length for uint32")
			}
			return 0, err
		}
		ret = uint64(binary.LittleEndian.Uint32(data))
		return ret, nil
	case 0xfd:
		data := make([]byte, 2)
		if _, err := io.ReadFull(r, data); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return 0, errors.New("invalid length for uint16")
			}
			return 0, err
		}
		ret = uint64(binary.LittleEndian.Uint16(data))
		return ret, nil
	default:
		// nolint:gosec // This isn't actually an issue, but the latest gosec is giving false positives
		return uint64(prefix[0]), nil
	}
}

func WriteUvarint(val uint64) []byte {
	var ret []byte
	switch {
	case val < 0xfd:
		ret = []byte{uint8(val)}
	case val <= math.MaxUint16:
		ret = make([]byte, 3)
		ret[0] = 0xfd // nolint:gosec // false positive for slice index out of bounds
		binary.LittleEndian.PutUint16(ret[1:], uint16(val))
	case val <= math.MaxUint32:
		ret = make([]byte, 5)
		ret[0] = 0xfe // nolint:gosec // false positive for slice index out of bounds
		binary.LittleEndian.PutUint32(ret[1:], uint32(val))
	default:
		ret = make([]byte, 9)
		ret[0] = 0xff // nolint:gosec // false positive for slice index out of bounds
		binary.LittleEndian.PutUint64(ret[1:], val)
	}
	return ret
}
