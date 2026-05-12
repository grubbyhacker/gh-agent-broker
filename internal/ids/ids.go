// Package ids creates broker operation identifiers.
package ids

import (
	"crypto/rand"
	"encoding/hex"
)

func NewOperationID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "op-unknown"
	}
	return "op-" + hex.EncodeToString(b[:])
}
