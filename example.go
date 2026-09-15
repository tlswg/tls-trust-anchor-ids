//go:build ignore

package main

import (
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

const (
	propertyTrustAnchorID          = 0
	propertyTrustAnchorGroups      = 1
	propertyTrustAnchorNegotiation = 2
)

type TrustAnchorID []uint64

func (id TrustAnchorID) String() string {
	var b strings.Builder
	for i, c := range id {
		if i != 0 {
			b.WriteByte('.')
		}
		fmt.Fprintf(&b, "%d", c)
	}
	return b.String()
}

func addBase128(out *cryptobyte.Builder, v uint64) {
	// Count how many bytes are needed.
	var l int
	for n := v; n != 0; n >>= 7 {
		l++
	}
	// Special-case: zero is encoded with one, not zero bytes.
	if v == 0 {
		l = 1
	}
	for ; l > 0; l-- {
		b := byte(v>>uint(7*(l-1))) & 0x7f
		if l > 1 {
			b |= 0x80
		}
		out.AddUint8(b)
	}
}

func readBase128(s *cryptobyte.String, out *uint64) bool {
	var b uint8
	if !s.ReadUint8(&b) || b == 0x80 {
		return false
	}
	val := uint64(b & 0x7f)
	for b&0x80 != 0 {
		if !s.ReadUint8(&b) || val > (math.MaxUint64>>7) {
			return false
		}
		val = (val << 7) | uint64(b&0x7f)
	}
	*out = val
	return true
}

func addTrustAnchorID(out *cryptobyte.Builder, id TrustAnchorID) {
	for _, v := range id {
		addBase128(out, v)
	}
}

func readTrustAnchorID(s *cryptobyte.String, out *TrustAnchorID) bool {
	var id TrustAnchorID
	for !s.Empty() {
		var v uint64
		if !readBase128(s, &v) {
			return false
		}
		id = append(id, v)
	}
	if len(id) == 0 {
		return false
	}
	*out = id
	return true
}

type ComponentRange struct {
	Min, Max      uint64
	MaxIsInfinity bool
}

type TrustAnchorIDPattern []ComponentRange

func (p TrustAnchorIDPattern) String() string {
	var b strings.Builder
	for i, c := range p {
		if i != 0 {
			b.WriteByte('.')
		}
		if c.MaxIsInfinity {
			fmt.Fprintf(&b, "{%d-}", c.Min)
		} else if c.Min == c.Max {
			fmt.Fprintf(&b, "%d", c.Min)
		} else {
			fmt.Fprintf(&b, "{%d-%d}", c.Min, c.Max)
		}
	}
	return b.String()
}

func addTrustAnchorIDPattern(out *cryptobyte.Builder, pattern TrustAnchorIDPattern) {
	for _, r := range pattern {
		addBase128(out, r.Min)
		if r.MaxIsInfinity {
			out.AddUint8(0x80)
		} else {
			addBase128(out, r.Max)
		}
	}
}

func readTrustAnchorIDPattern(s *cryptobyte.String, out *TrustAnchorIDPattern) bool {
	var pattern TrustAnchorIDPattern
	for !s.Empty() {
		var min uint64
		if !readBase128(s, &min) || s.Empty() {
			return false
		}
		if (*s)[0] == 0x80 {
			s.Skip(1)
			pattern = append(pattern, ComponentRange{Min: min, MaxIsInfinity: true})
		} else {
			var max uint64
			if !readBase128(s, &max) {
				return false
			}
			pattern = append(pattern, ComponentRange{Min: min, Max: max})
		}
	}
	if len(pattern) == 0 {
		return false
	}
	*out = pattern
	return true
}

type UnknownProperty struct {
	Type uint16
	Data []byte
}

type CertificatePropertyList struct {
	TrustAnchorID          TrustAnchorID
	TrustAnchorGroups      []TrustAnchorIDPattern
	TrustAnchorNegotiation bool
	UnknownProperties      []UnknownProperty
}

func (l *CertificatePropertyList) Marshal() ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(props *cryptobyte.Builder) {
		if len(l.TrustAnchorID) != 0 {
			props.AddUint16(propertyTrustAnchorID)
			props.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
				// No extra length prefix because we said that the `data` field
				// simply is the trust anchor ID.
				addTrustAnchorID(child, l.TrustAnchorID)
			})
		}
		if len(l.TrustAnchorGroups) != 0 {
			props.AddUint16(propertyTrustAnchorGroups)
			// TLS's presentation language leads to many redundant length prefixes.
			// First we have a length prefix for the property's `data` field.
			props.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
				// Now the TrustAnchorIDPatternList needs a length prefix.
				child.AddUint16LengthPrefixed(func(list *cryptobyte.Builder) {
					for _, p := range l.TrustAnchorGroups {
						// The ID is encoded as a TrustAnchorIDPattern, so it needs a length prefix,
						// or the parsing will be ambiguous.
						list.AddUint8LengthPrefixed(func(pattern *cryptobyte.Builder) {
							addTrustAnchorIDPattern(pattern, p)
						})
					}
				})
			})
		}
		if l.TrustAnchorNegotiation {
			props.AddUint16(propertyTrustAnchorNegotiation)
			props.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {})
		}
	})
	return b.Bytes()
}

func parseCertificatePropertyList(in []byte) (*CertificatePropertyList, error) {
	s := cryptobyte.String(in)
	var props cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&props) || !s.Empty() {
		return nil, errors.New("invalid CertificatePropertyList")
	}
	var out CertificatePropertyList
	var lastType uint16
	hasLastType := false
	for !props.Empty() {
		var propType uint16
		var data cryptobyte.String
		if !props.ReadUint16(&propType) || !props.ReadUint16LengthPrefixed(&data) {
			return nil, errors.New("invalid property")
		}
		if hasLastType && propType <= lastType {
			return nil, errors.New("properties must be strictly sorted by type")
		}
		lastType = propType
		hasLastType = true

		switch propType {
		case propertyTrustAnchorID:
			if len(data) > 255 || !readTrustAnchorID(&data, &out.TrustAnchorID) {
				return nil, errors.New("invalid trust_anchor_id")
			}
		case propertyTrustAnchorGroups:
			var list cryptobyte.String
			if !data.ReadUint16LengthPrefixed(&list) || !data.Empty() || list.Empty() {
				return nil, errors.New("invalid trust_anchor_groups")
			}
			for !list.Empty() {
				var p cryptobyte.String
				var pattern TrustAnchorIDPattern
				if !list.ReadUint8LengthPrefixed(&p) || !readTrustAnchorIDPattern(&p, &pattern) {
					return nil, errors.New("invalid trust_anchor_groups pattern")
				}
				out.TrustAnchorGroups = append(out.TrustAnchorGroups, pattern)
			}
		case propertyTrustAnchorNegotiation:
			if !data.Empty() {
				return nil, errors.New("invalid trust_anchor_negotiation")
			}
			out.TrustAnchorNegotiation = true
		default:
			out.UnknownProperties = append(out.UnknownProperties, UnknownProperty{
				Type: propType,
				Data: append([]byte(nil), data...),
			})
		}
	}
	return &out, nil
}

func printProperties(props *CertificatePropertyList) {
	var numProps int
	if len(props.TrustAnchorID) != 0 {
		numProps++
		fmt.Printf("- trust_anchor_id: %s\n", props.TrustAnchorID)
	}
	if len(props.TrustAnchorGroups) != 0 {
		numProps++
		fmt.Printf("- trust_anchor_groups:\n")
		for _, g := range props.TrustAnchorGroups {
			fmt.Printf("    %s\n", g)
		}
	}
	if props.TrustAnchorNegotiation {
		numProps++
		fmt.Printf("- trust_anchor_negotiation\n")
	}
	for _, p := range props.UnknownProperties {
		numProps++
		if len(p.Data) == 0 {
			fmt.Printf("- unknown property %d\n", p.Type)
		} else {
			fmt.Printf("- unknown property %d: %x\n", p.Type, p.Data)
		}
	}
	if numProps == 0 {
		fmt.Printf("(empty)\n")
	}
}

func printExample() {
	props := CertificatePropertyList{
		TrustAnchorID: []uint64{32473, 1},
		TrustAnchorGroups: []TrustAnchorIDPattern{
			{{Min: 2187, Max: 2187}, {Min: 2, Max: 2}, {Min: 100, Max: 200}},
			{{Min: 32473, Max: 32473}, {Min: 3, Max: 3}, {Min: 42, MaxIsInfinity: true}, {Min: 100, Max: 200}},
		},
		TrustAnchorNegotiation: true,
	}
	b, err := props.Marshal()
	if err != nil {
		panic(err)
	}
	printProperties(&props)

	fmt.Printf("\nhex: %x\n", b)
	fmt.Printf("\nPEM:\n")
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE PROPERTIES", Bytes: b})
}

func parsePEM(path string) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %s\n", path, err)
		os.Exit(1)
	}
	var count int
	for len(bytes) > 0 {
		var block *pem.Block
		block, bytes = pem.Decode(bytes)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE PROPERTIES" {
			props, err := parseCertificatePropertyList(block.Bytes)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing CertificatePropertyList: %s\n", err)
				os.Exit(1)
			}
			fmt.Printf("Properties found in %s:\n", path)
			printProperties(props)
			fmt.Printf("\n")
			count++
		}
	}
	if count == 0 {
		fmt.Fprintf(os.Stderr, "No CERTIFICATE PROPERTIES blocks found in %s\n", path)
		os.Exit(1)
	}
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		printExample()
	}

	for _, arg := range args {
		parsePEM(arg)
	}
}
