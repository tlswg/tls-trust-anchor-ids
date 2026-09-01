//go:build ignore

package main

import (
	"encoding/pem"
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

func addTrustAnchorID(out *cryptobyte.Builder, id TrustAnchorID) {
	for _, v := range id {
		addBase128(out, v)
	}
}

type ComponentRange struct {
	Min, Max uint64
}

type TrustAnchorIDPattern []ComponentRange

func (p TrustAnchorIDPattern) String() string {
	var b strings.Builder
	for i, c := range p {
		if i != 0 {
			b.WriteByte('.')
		}
		if c.Min == c.Max {
			fmt.Fprintf(&b, "%d", c.Min)
		} else if c.Max == math.MaxUint64 {
			fmt.Fprintf(&b, "{%d-}", c.Min)
		} else {
			fmt.Fprintf(&b, "{%d-%d}", c.Min, c.Max)
		}
	}
	return b.String()
}

func addTrustAnchorIDPattern(out *cryptobyte.Builder, pattern TrustAnchorIDPattern) {
	for _, r := range pattern {
		addBase128(out, r.Min)
		addBase128(out, r.Max)
	}
}

type CertificatePropertyList struct {
	TrustAnchorID          TrustAnchorID
	TrustAnchorGroups      []TrustAnchorIDPattern
	TrustAnchorNegotiation bool
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

func main() {
	props := CertificatePropertyList{
		TrustAnchorID: []uint64{32473, 1},
		TrustAnchorGroups: []TrustAnchorIDPattern{
			{{Min: 2187, Max: 2187}, {Min: 2, Max: 2}, {Min: 100, Max: 200}},
			{{Min: 32473, Max: 32473}, {Min: 3, Max: 3}, {Min: 42, Max: math.MaxUint64}, {Min: 100, Max: 200}},
		},
		TrustAnchorNegotiation: true,
	}
	b, err := props.Marshal()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Properties:\n")
	if len(props.TrustAnchorID) != 0 {
		fmt.Printf("- Issued by CA with ID %s\n", props.TrustAnchorID)
	}
	if len(props.TrustAnchorGroups) != 0 {
		fmt.Printf("- CA is in trust anchor groups:\n")
		for _, g := range props.TrustAnchorGroups {
			fmt.Printf("    %s\n", g)
		}
	}
	if props.TrustAnchorNegotiation {
		fmt.Printf("- Should only be used if trust anchors match\n")
	} else {
		fmt.Printf("- May be used as a fallback if trust anchors do not match\n")
	}

	fmt.Printf("\nhex: %x\n", b)
	fmt.Printf("\nPEM:\n")
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE PROPERTIES", Bytes: b})
}
