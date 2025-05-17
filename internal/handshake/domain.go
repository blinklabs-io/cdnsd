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
	"fmt"
	"io"
	"net"
)

const (
	DnsMaxName  = 255
	DnsMaxLabel = 63
)

// Record types
const (
	RecordTypeDS     = 0
	RecordTypeNS     = 1
	RecordTypeGLUE4  = 2
	RecordTypeGLUE6  = 3
	RecordTypeSYNTH4 = 4
	RecordTypeSYNTH6 = 5
	RecordTypeTEXT   = 6
)

type BytesReader struct {
	*bytes.Buffer
	origBytes []byte
}

func NewBytesReader(buf []byte) *BytesReader {
	ret := &BytesReader{
		Buffer: bytes.NewBuffer(buf),
	}
	if buf != nil {
		ret.origBytes = make([]byte, len(buf))
		copy(ret.origBytes, buf)
	}
	return ret
}

func (b *BytesReader) OriginalBytes() []byte {
	return b.origBytes
}

type DomainResourceData struct {
	Version uint8
	Records []DomainRecord
}

func NewDomainResourceDataFromBytes(data []byte) (*DomainResourceData, error) {
	ret := &DomainResourceData{}
	if err := ret.decode(data); err != nil {
		return nil, err
	}
	return ret, nil
}

func (d *DomainResourceData) decode(data []byte) error {
	r := NewBytesReader(data)
	var err error
	// Version
	if err = binary.Read(r, binary.LittleEndian, &d.Version); err != nil {
		return err
	}
	// Records
	var recordType uint8
	var record DomainRecord
	for {
		// Read record type
		if err = binary.Read(r, binary.LittleEndian, &recordType); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		switch recordType {
		case RecordTypeDS:
			record = &DsDomainRecord{}
		case RecordTypeNS:
			record = &NsDomainRecord{}
		case RecordTypeGLUE4:
			record = &Glue4DomainRecord{}
		case RecordTypeGLUE6:
			record = &Glue6DomainRecord{}
		case RecordTypeSYNTH4:
			record = &Synth4DomainRecord{}
		case RecordTypeSYNTH6:
			record = &Synth6DomainRecord{}
		case RecordTypeTEXT:
			record = &TextDomainRecord{}
		default:
			return fmt.Errorf("unsupported record type %d", recordType)
		}
		if record != nil {
			err = record.decode(r)
			if err != nil {
				return err
			}
		}
		d.Records = append(d.Records, record)
	}
	return nil
}

type DomainRecord interface {
	isDomainRecord()
	decode(*BytesReader) error
}

type Glue4DomainRecord struct {
	Name    string
	Address net.IP
}

func (*Glue4DomainRecord) isDomainRecord() {}

func (g *Glue4DomainRecord) decode(r *BytesReader) error {
	name, err := domainRecordNameDecode(r)
	if err != nil {
		return err
	}
	g.Name = name
	addr, err := domainRecordIPv4Decode(r)
	if err != nil {
		return err
	}
	g.Address = addr
	return nil
}

type Glue6DomainRecord struct {
	Name    string
	Address net.IP
}

func (*Glue6DomainRecord) isDomainRecord() {}

func (g *Glue6DomainRecord) decode(r *BytesReader) error {
	name, err := domainRecordNameDecode(r)
	if err != nil {
		return err
	}
	g.Name = name
	addr, err := domainRecordIPv6Decode(r)
	if err != nil {
		return err
	}
	g.Address = addr
	return nil
}

type NsDomainRecord struct {
	Name string
}

func (*NsDomainRecord) isDomainRecord() {}

func (n *NsDomainRecord) decode(r *BytesReader) error {
	name, err := domainRecordNameDecode(r)
	if err != nil {
		return err
	}
	n.Name = name
	return nil
}

type DsDomainRecord struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     []byte
}

func (*DsDomainRecord) isDomainRecord() {}

func (d *DsDomainRecord) decode(r *BytesReader) error {
	if err := binary.Read(r, binary.BigEndian, &d.KeyTag); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &d.Algorithm); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &d.DigestType); err != nil {
		return err
	}
	var size uint8
	if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
		return err
	}
	d.Digest = make([]byte, size)
	if err := binary.Read(r, binary.LittleEndian, &d.Digest); err != nil {
		return err
	}
	return nil
}

type Synth4DomainRecord struct {
	Address net.IP
}

func (*Synth4DomainRecord) isDomainRecord() {}

func (s *Synth4DomainRecord) decode(r *BytesReader) error {
	addr, err := domainRecordIPv4Decode(r)
	if err != nil {
		return err
	}
	s.Address = addr
	return nil
}

type Synth6DomainRecord struct {
	Address net.IP
}

func (*Synth6DomainRecord) isDomainRecord() {}

func (s *Synth6DomainRecord) decode(r *BytesReader) error {
	addr, err := domainRecordIPv6Decode(r)
	if err != nil {
		return err
	}
	s.Address = addr
	return nil
}

type TextDomainRecord struct {
	Items [][]byte
}

func (*TextDomainRecord) isDomainRecord() {}

func (t *TextDomainRecord) decode(r *BytesReader) error {
	// Read length of items list
	var length uint8
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return err
	}
	var size uint8
	for range int(length) {
		// Read item size
		if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
			return err
		}
		// Read item
		buf := make([]byte, size)
		if err := binary.Read(r, binary.LittleEndian, &buf); err != nil {
			return err
		}
		t.Items = append(t.Items, buf)
	}
	return nil
}

func domainRecordIPv4Decode(r *BytesReader) (net.IP, error) {
	var ret net.IP
	buf := make([]byte, 4)
	if err := binary.Read(r, binary.LittleEndian, &buf); err != nil {
		return ret, err
	}
	ret = net.IP(buf)
	return ret, nil
}

func domainRecordIPv6Decode(r *BytesReader) (net.IP, error) {
	var ret net.IP
	buf := make([]byte, 16)
	if err := binary.Read(r, binary.LittleEndian, &buf); err != nil {
		return ret, err
	}
	ret = net.IP(buf)
	return ret, nil
}

func domainRecordNameDecode(r *BytesReader) (string, error) {
	// NOTE: this function is mostly ported straight from hnsd
	var name string
	for {
		c, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if c == 0x00 {
			break
		}
		switch c & 0xc0 {
		case 0x00:
			if c > DnsMaxLabel {
				return "", errors.New("label too long")
			}
			for range int(c) {
				b, err := r.ReadByte()
				if err != nil {
					return "", err
				}
				// Replace NULL
				// This is necessary for C-style strings, but probably not for Go
				if b == 0x00 {
					b = 0xff
				}
				// Replace period to prevent double-period
				if b == 0x2e {
					b = 0xfe
				}
				name += string([]byte{b})
			}
			if len(name) > 0 {
				name += "."
			}
		case 0xc0:
			// Lookup name from earlier in the buffer
			c1, err := r.ReadByte()
			if err != nil {
				return "", err
			}
			// Set new 16-bit offset value based on the lower 6 bits of our original
			// byte and the additional byte we just read above
			offset := (int(c^0xc0) << 8) | int(c1)
			// Replace buffer with original bytes
			data := r.OriginalBytes()
			r = NewBytesReader(data)
			// Read and discard bytes until we reach the calculated offset
			for range offset {
				if _, err := r.ReadByte(); err != nil {
					return "", err
				}
			}
		default:
			return "", errors.New("unexpected value")
		}
	}
	return name, nil
}
