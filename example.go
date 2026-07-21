//go:build ignore

package main

import (
	"encoding/pem"
	"fmt"
	"math"
	"os"

	"golang.org/x/crypto/cryptobyte"
)

const (
	propertyTrustAnchorID              = 0
	propertyTrustAnchorGroupInclusions = 1
	propertyNegotiationOptional        = 2
)

type TrustAnchorID []uint64

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

type TrustAnchorRange struct {
	Base     TrustAnchorID
	Min, Max uint64
}

type CertificatePropertyList struct {
	TrustAnchorID              TrustAnchorID
	TrustAnchorGroupInclusions []TrustAnchorRange
	NegotiationOptional        bool
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
		if len(l.TrustAnchorGroupInclusions) != 0 {
			props.AddUint16(propertyTrustAnchorGroupInclusions)
			// TLS's presentation language leads to many redundant length prefixes.
			// First we have a length prefix for the property's `data` field.
			props.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
				// Now the TrustAnchorRangeList needs a length prefix.
				child.AddUint16LengthPrefixed(func(list *cryptobyte.Builder) {
					for _, r := range l.TrustAnchorGroupInclusions {
						// The ID is encoded as a TrustAnchorID, so it needs a length prefix,
						// or the parsing will be ambiguous.
						list.AddUint8LengthPrefixed(func(id *cryptobyte.Builder) {
							addTrustAnchorID(id, r.Base)
						})
						list.AddUint64(r.Min)
						list.AddUint64(r.Max)
					}
				})
			})
		}
		if l.NegotiationOptional {
			props.AddUint16(propertyNegotiationOptional)
			props.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {})
		}
	})
	return b.Bytes()
}

func main() {
	props := CertificatePropertyList{
		TrustAnchorID: []uint64{32473, 1},
		TrustAnchorGroupInclusions: []TrustAnchorRange{
			{Base: []uint64{2187, 2}, Min: 100, Max: 200},
			{Base: []uint64{32473, 3}, Min: 42, Max: math.MaxUint64},
		},
		NegotiationOptional: true,
	}
	b, err := props.Marshal()
	if err != nil {
		panic(err)
	}
	fmt.Printf("hex: %x\n", b)
	fmt.Printf("PEM:\n")
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE PROPERTIES", Bytes: b})
}
