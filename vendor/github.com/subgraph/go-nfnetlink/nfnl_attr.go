package nfnetlink

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"syscall"
	"net"
)

// NLAttr represents a single netlink attribute.
type NLAttr struct {
	Type   uint16
	Data   []byte
	nested *NLAttrSet
	Nested bool
	Len    uint16
}

type NLAttrSet struct {
	attrList []*NLAttr // list of attributes
	attrMap map[uint16]*NLAttr // mapping of attributes by type
}

func NewNLAttrSet() *NLAttrSet {
	return &NLAttrSet{
		attrMap: make(map[uint16]*NLAttr),
	}
}

func (as *NLAttrSet) String() string {
	bb := new(bytes.Buffer)
	for i,a := range as.attrList {
		if i != 0 {
			bb.WriteString(" ")
		}
		bb.WriteString(a.String())
	}
	return bb.String()
}

func (as *NLAttrSet) Add(a *NLAttr) {
	as.attrList = append(as.attrList, a)
	t := a.Type & ^uint16(syscall.NLA_F_NESTED)
	as.attrMap[t] = a
}

func (as *NLAttrSet) Get(atypes ...uint16) *NLAttr {
	if len(atypes) == 0 {
		return nil
	}
	attr := as.attrMap[atypes[0]]
	return attr.Get(atypes[1:]...)
}

func (as *NLAttrSet) WriteTo(bb *bytes.Buffer) {
	for _,a := range as.attrList {
		a.WriteTo(bb)
	}
}

func (as *NLAttrSet) Size() int {
	var sz int
	for _,a := range as.attrList {
		if !a.Nested {
			sz += a.Size()
		} else {
			sz += 4
		}
	}
	return sz
}

// nlaAlignOf returns attrlen aligned to a 4 byte boundary
func nlaAlignOf(attrlen int) int {
	return (attrlen + syscall.NLA_ALIGNTO - 1) & ^(syscall.NLA_ALIGNTO - 1)
}

// NewAttrFromFields creates and returns a new NLAttr instance by serializing the provided
// fields into a slice of bytes which is stored as the Data element of the attribute.
func NewAttrFromFields(atype uint16, fields ...interface{}) (*NLAttr, error) {
	b := new(bytes.Buffer)
	for _, f := range fields {
		if err := binary.Write(b, binary.BigEndian, f); err != nil {
			return nil, err
		}
	}
	return NewAttr(atype, b.Bytes()), nil
}

// NewAttr creates and returns a new NLAttr instance from the provided type and data payload
func NewAttr(atype uint16, data []byte) *NLAttr {
	return &NLAttr{
		Type: atype,
		Data: data,
		Nested: false,
	}
}

func NewAttrNested(atype uint16, alen uint16) *NLAttr {
	return &NLAttr{
		Type:   atype,
		Len:    alen,
		Data:   nil,
		Nested: true,
	}
}

func (a *NLAttr) String() string {
	if a.Type & syscall.NLA_F_NESTED != 0 {
		t := a.Type & ^uint16(syscall.NLA_F_NESTED)
		return fmt.Sprintf("(%d %v)", t, a.nested)
	}
	return fmt.Sprintf("(%d %s)", a.Type, hex.EncodeToString(a.Data))
}

// ParseAttr reads a serialized attribute from r and parses it into an NLAttr instance.
func ParseAttr(r *bytes.Reader) (*NLAttr, error) {
	attr := &NLAttr{}
	if err := attr.parse(r); err != nil {
		return nil, err
	}
	if attr.Type & syscall.NLA_F_NESTED != 0 {
		if err := attr.parseNested(); err != nil {
			return nil, err
		}
	}

	return attr, nil
}

// parse reads a serialized attribute from r and parses it into this NLAttr instance.
func (a *NLAttr) parse(r *bytes.Reader) error {
	if r.Len() < syscall.NLA_HDRLEN {
		return errors.New("Truncated attribute")
	}
	var alen uint16
	binary.Read(r, native, &alen)
	binary.Read(r, native, &a.Type)

	if alen < syscall.NLA_HDRLEN || int(alen - syscall.NLA_HDRLEN) > r.Len() {
		return errors.New("Truncated attribute")
	}
	alen -= syscall.NLA_HDRLEN
	if alen == 0 {
		a.Data = nil
		return nil
	}

	a.Data = make([]byte, alen)
	r.Read(a.Data)
	padlen := nlaAlignOf(int(alen)) - int(alen)
	for i := 0; i < padlen; i++ {
		r.ReadByte()
	}
	return nil
}

// Size returns the size in bytes of this attribute when serialized
func (a *NLAttr) Size() int {
	if a.Nested {
		return syscall.NLA_HDRLEN + nlaAlignOf(int(a.Len))
	}
	return syscall.NLA_HDRLEN + nlaAlignOf(len(a.Data))
}

// serialize the attribute and return the raw bytes
func (a *NLAttr) serialize() []byte {
	bs := new(bytes.Buffer)
	a.WriteTo(bs)
	return bs.Bytes()
}

// WriteTo serializes the attribute instance into the provided bytes.Buffer
func (a *NLAttr) WriteTo(b *bytes.Buffer) {

	if a.Nested {
		binary.Write(b, native, uint16(a.Len))
		binary.Write(b, native, uint16(a.Type))
		return
	}

	alen := syscall.NLA_HDRLEN + len(a.Data)
	binary.Write(b, native, uint16(alen))
	binary.Write(b, native, a.Type)
	b.Write(a.Data)
	a.writePadding(b)
}

// ReadFields parses the attribute data into the provided array of
// fields using binary.Read() to parse each individual field.
func (a *NLAttr) ReadFields(fields ...interface{}) error {
	if a == nil {
		return nil
	}
	r := bytes.NewReader(a.Data)
	for _, f := range fields {
		if err := binary.Read(r, binary.BigEndian, f); err != nil {
			return err
		}
	}
	return nil
}

func (a *NLAttr) Get(atypes ...uint16) *NLAttr {
	if len(atypes) == 0 {
		return a
	}
	if a == nil  || a.nested == nil {
		return nil
	}
	head := atypes[0]
	tail := atypes[1:]
	return a.nested.attrMap[head].Get(tail...)
}

func (a *NLAttr) AsIPv4(ip *net.IP) bool {
	if a == nil {
		return false
	}
	var n uint32
	if err := a.ReadFields(&n); err != nil {
		return false
	}
	*ip = net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	return true
}

func (a *NLAttr) parseNested() error {
	as := NewNLAttrSet()
	r := bytes.NewReader(a.Data)
	for r.Len() >= syscall.NLA_HDRLEN {
		attr, err := ParseAttr(r)
		if err != nil {
			return err
		}
		as.Add(attr)
	}
	a.nested = as
	return nil
}

// writePadding is called while serializing the attribute instance to write
// an appropriate number of '0' bytes to the buffer b so that the length of
// data in the buffer is 4 byte aligned
func (a *NLAttr) writePadding(b *bytes.Buffer) {
	padlen := a.Size() - (syscall.NLA_HDRLEN + len(a.Data))
/*	if a.Nested {
		padlen = a.Size() - (syscall.NLA_HDRLEN + int(a.Len))
	} */

	for i := 0; i < padlen; i++ {
		b.WriteByte(0)
	}
}
