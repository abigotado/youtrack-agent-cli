package intent

import (
	"encoding/base32"
	"fmt"
)

const (
	planIDPrefix       = "YTAP-"
	planIDPayloadBytes = 16
	planIDEncodedBytes = 26
)

// ValidatePlanID requires the single canonical encoding of a 128-bit plan ID:
// YTAP- followed by uppercase RFC 4648 Base32 without padding. Decode/re-encode
// equality rejects non-zero unused bits in the final symbol.
func ValidatePlanID(value string) error {
	if len(value) != len(planIDPrefix)+planIDEncodedBytes || value[:len(planIDPrefix)] != planIDPrefix {
		return fmt.Errorf("%w: plan ID has the wrong prefix or length", ErrInvalidPlan)
	}
	encoded := value[len(planIDPrefix):]
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
	if err != nil || len(raw) != planIDPayloadBytes || base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw) != encoded {
		return fmt.Errorf("%w: plan ID is not canonical 128-bit unpadded base32", ErrInvalidPlan)
	}
	return nil
}
