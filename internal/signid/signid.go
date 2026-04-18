// Package signid derives a short correlation id for a sign request.
//
// The id is the first 7 hex characters of the input, matching git's
// short-hash convention. linux-id and ssh-agent-mux compute the id over
// the same source bytes (clientDataHash for CTAP2, ChallengeParam for
// CTAP1) so the two notifications about a single sign request carry the
// same id and the user can visually confirm that the prompt belongs to
// the SSH session they expect.
//
// 28 bits is enough entropy for in-the-moment visual matching; this is
// not a security primitive.
package signid

import "encoding/hex"

const length = 7

func From(b []byte) string {
	full := hex.EncodeToString(b)
	if len(full) > length {
		return full[:length]
	}
	return full
}
