// Package signid derives a short correlation id for a sign request.
//
// Both the short id and the full hash are encoded in standard base64
// without padding, matching the OpenSSH `SHA256:<base64>` fingerprint
// convention. The short id is the first 7 characters of the full
// encoding so it is always a literal prefix of the long form.
//
// linux-id and ssh-agent-mux compute the id over the same source bytes
// (clientDataHash for CTAP2, ChallengeParam for CTAP1; SHA-256 of the
// raw sign data on the mux side) so the two notifications about a
// single sign request carry the same id, and the user can visually
// confirm that the prompt belongs to the SSH session they expect.
//
// 7 base64 chars ≈ 42 bits — enough entropy for in-the-moment visual
// matching. This is not a security primitive.
package signid

import "encoding/base64"

const length = 7

// Full returns the full base64 (no padding) encoding of b. For CTAP2 b
// is the 32-byte clientDataHash; for CTAP1 it is the 32-byte
// ChallengeParam. Used for forensic log lines where a short id might
// collide.
func Full(b []byte) string {
	return base64.RawStdEncoding.EncodeToString(b)
}

// From returns the short id used in user-visible prompts and
// notifications. It is always a prefix of Full(b).
func From(b []byte) string {
	full := Full(b)
	if len(full) > length {
		return full[:length]
	}
	return full
}
