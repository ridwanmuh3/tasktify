package fndsa

import (
	"bytes"
	"crypto"
	"io"
	"testing"
)

// ════════════════════════════════════════════════════════════════════════
// Adversarial tests against the FN-DSA/Falcon signature PRIMITIVE.
//
// Why this file exists (separate from pkg/jwt and k6/adversarial_jwt.js):
//
// The JWT-level adversarial suite (backend/k6/adversarial_jwt.js,
// pkg/jwt/jwt_confusion_attack_test.go) is grounded in RFC 7519 (JSON Web
// Token) and RFC 8725 (JWT Best Current Practices). Those RFCs define the
// JOSE *envelope*: header "alg" verification, "exp"/"iat" claims, compact
// serialization parsing. They say nothing about whether the underlying
// FN-DSA signature scheme itself resists forgery — that is a property of
// the cryptographic primitive, not the token format wrapped around it. A
// forged-header test can only prove the envelope-parsing code is correct;
// it cannot substantiate a claim about FN-DSA's own security. Any thesis
// claim that "FN-DSA resists adversarial forgery" therefore needs tests
// that call fndsa.Sign/fndsa.Verify directly, bypassing pkg/jwt, JSON, and
// base64url entirely.
//
// References for the vectors below:
//
//   - Fouque, Hoffstein, Kirchner, Lyubashevsky, Pornin, Prest, Ricosset,
//     Seiler, Whyte, Zhang. "Falcon: Fast-Fourier Lattice-based Compact
//     Signatures over NTRU" (NIST PQC Round 3 submission).
//     https://falcon-sign.info/falcon.pdf
//     — Verify algorithm accepts a signature (s1, s2) iff it decodes
//     correctly AND ||(s1, s2)|| <= beta (the norm bound). This repo's
//     Verify() implements that check as mqpoly_sqnorm_is_acceptable()
//     against the sqbeta[] table (see mq.go, vrfy.go).
//
//   - Goldwasser, Micali, Rivest. "A Digital Signature Scheme Secure
//     Against Adaptive Chosen-Message Attacks." SIAM J. Computing 17(2),
//     1988. Defines EUF-CMA (existential unforgeability under chosen-
//     message attack) — the formal security goal any digital signature
//     scheme, including FN-DSA, is required to satisfy independent of any
//     transport/envelope format. Cross-key and tampered-input rejection
//     are minimum necessary (not sufficient) conditions for EUF-CMA.
//
//   - NIST FIPS 206 (FN-DSA, Falcon) — the standardization of Falcon is
//     in progress; as of this writing the Initial Public Draft has not
//     been published to a stable public URL (NIST PQC forum status
//     updates, late 2025: draft in NIST/DoC clearance). The Round-3
//     Falcon specification above is the authoritative source these tests
//     target; once FIPS 206 is published, its Verify algorithm section
//     should be cited in addition.
//
//   - Domain-separation context (ctx) mixing: this implementation hashes
//     ctx and the hashed verifying key into the signed digest
//     (hash_to_point, util.go) before the pre-hash identifier and message
//     — the same "context string" construction NIST specifies for
//     lattice signatures (see FIPS 204 §5.4-style Mu computation) to stop
//     a signature produced for one protocol/context being replayed as
//     valid in another. TestAttack_DomainContextConfusion exercises this
//     directly.
// ════════════════════════════════════════════════════════════════════════

// TestAttack_SignatureNormBoundRejection exercises the exact acceptance
// criterion of the Falcon Verify algorithm: a candidate signature is only
// valid if its squared norm is <= the per-degree bound (sqbeta[logn]).
// This is not a JOSE/JWT concept — it is FN-DSA's own forgery-resistance
// check, unrelated to any header or claim.
//
// Not run per signerVariant: the norm bound is enforced by Verify() on the
// decoded (s1, s2), which is identical code regardless of whether the
// signature came from the original or precomputed signer — precomputation
// only changes trapdoor/basis preparation at signing time, not this
// verification-side check. TestAttack_CrossKeyForgery,
// TestAttack_DomainContextConfusion, TestAttack_PreHashIdentifierConfusion
// and TestAttack_TruncatedSignatureRejected below each still exercise a
// Verify() call against signatures from both variants, so this criterion
// is indirectly confirmed identical for both anyway.
func TestAttack_SignatureNormBoundRejection(t *testing.T) {
	for _, logn := range []uint{9, 10} {
		t.Run(signatureAlgName(logn), func(t *testing.T) {
			bound := sqbeta[logn]

			if !mqpoly_sqnorm_is_acceptable(logn, bound) {
				t.Fatalf("VULNERABLE-INVERTED: norm exactly at bound (%d) incorrectly rejected", bound)
			}
			if mqpoly_sqnorm_is_acceptable(logn, bound+1) {
				t.Fatalf("VULNERABLE: norm one above bound (%d) incorrectly accepted — forged over-norm signature would verify", bound+1)
			}
			if mqpoly_sqnorm_is_acceptable(logn, bound*4) {
				t.Fatalf("VULNERABLE: grossly over-bound norm (%d) incorrectly accepted", bound*4)
			}

			t.Logf("PROTECTED: norm bound sqbeta[%d]=%d enforced correctly", logn, bound)
		})
	}
}

func signatureAlgName(logn uint) string {
	switch logn {
	case 9:
		return "FN-DSA-512"
	case 10:
		return "FN-DSA-1024"
	default:
		return "FN-DSA-weak"
	}
}

// signerVariant lets every adversarial test below run once against the
// original (dynamic) signer and once against PrecomputedSigner (the
// proposed optimization) with identical inputs, so a passing/failing
// result is directly comparable between "Falcon" (baseline, FN-DSA-512
// dynamic signing) and "Falcon Precomputed" (FN-DSA-Precomputed-512).
// Precomputation only changes how the signer prepares the trapdoor basis
// and LDL tree at startup (see docs/research-system-architecture.md
// "Optimized Method Used") — it must not change forgery resistance, and
// these paired subtests are the evidence for that claim.
type signerVariant struct {
	name string
	sign func(rng io.Reader, ctx DomainContext, id crypto.Hash, data []byte) ([]byte, error)
}

func signerVariants(t *testing.T, sk []byte) []signerVariant {
	t.Helper()
	ps, err := NewPrecomputedSigner(sk)
	if err != nil {
		t.Fatalf("precompute failed: %v", err)
	}
	return []signerVariant{
		{
			name: "Falcon (FN-DSA-512 original/dynamic)",
			sign: func(rng io.Reader, ctx DomainContext, id crypto.Hash, data []byte) ([]byte, error) {
				return Sign(rng, sk, ctx, id, data)
			},
		},
		{
			name: "Falcon Precomputed (FN-DSA-Precomputed-512)",
			sign: func(rng io.Reader, ctx DomainContext, id crypto.Hash, data []byte) ([]byte, error) {
				return ps.Sign(rng, ctx, id, data)
			},
		},
	}
}

// TestAttack_CrossKeyForgery: a signature produced under attacker-controlled
// key A must not verify under an unrelated victim key B. This is the
// pure-signature analog of pkg/jwt's TestAttack_CrossKeyVerification, and
// the minimal necessary condition for EUF-CMA (Goldwasser/Micali/Rivest
// 1988) — a scheme where any key's signature verifies under any other
// key's public key trivially admits existential forgery. Run against both
// Falcon (original) and Falcon Precomputed to prove the optimization does
// not weaken this property.
func TestAttack_CrossKeyForgery(t *testing.T) {
	skA, _, err := KeyGen(9, nil)
	if err != nil {
		t.Fatalf("keygen A failed: %v", err)
	}
	_, vkB, err := KeyGen(9, nil)
	if err != nil {
		t.Fatalf("keygen B failed: %v", err)
	}

	for _, variant := range signerVariants(t, skA) {
		t.Run(variant.name, func(t *testing.T) {
			data := []byte("cross-key forgery attempt")
			sig, err := variant.sign(nil, DOMAIN_NONE, 0, data)
			if err != nil {
				t.Fatalf("sign failed: %v", err)
			}

			if Verify(vkB, DOMAIN_NONE, 0, data, sig) {
				t.Fatal("VULNERABLE: signature from key A verified under unrelated key B's public key")
			}
			t.Log("PROTECTED: cross-key forgery rejected at the raw signature level")
		})
	}
}

// TestAttack_DomainContextConfusion: a signature bound to one domain
// context must not verify under a different context, and a context-bound
// signature must not verify as DOMAIN_NONE (or vice versa). ctx is mixed
// into hash_to_point() alongside the hashed verifying key before the
// message is hashed to a lattice point, so a mismatched ctx should produce
// an entirely different target point and fail well before the norm check.
// Run against both Falcon (original) and Falcon Precomputed.
func TestAttack_DomainContextConfusion(t *testing.T) {
	sk, vk, err := KeyGen(9, nil)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	data := []byte("context-bound message")
	ctxA := DomainContext([]byte("tasktify-protocol-A"))
	ctxB := DomainContext([]byte("tasktify-protocol-B"))

	for _, variant := range signerVariants(t, sk) {
		t.Run(variant.name, func(t *testing.T) {
			sigA, err := variant.sign(nil, ctxA, 0, data)
			if err != nil {
				t.Fatalf("sign under ctxA failed: %v", err)
			}

			if Verify(vk, ctxB, 0, data, sigA) {
				t.Fatal("VULNERABLE: signature bound to ctxA verified under a different context ctxB")
			}
			if Verify(vk, DOMAIN_NONE, 0, data, sigA) {
				t.Fatal("VULNERABLE: context-bound signature verified as DOMAIN_NONE")
			}
			if !Verify(vk, ctxA, 0, data, sigA) {
				t.Fatal("BROKEN: signature rejected under its own correct context")
			}

			sigNone, err := variant.sign(nil, DOMAIN_NONE, 0, data)
			if err != nil {
				t.Fatalf("sign under DOMAIN_NONE failed: %v", err)
			}
			if Verify(vk, ctxA, 0, data, sigNone) {
				t.Fatal("VULNERABLE: DOMAIN_NONE signature verified under a named context")
			}

			t.Log("PROTECTED: domain-separation context mismatch correctly rejected")
		})
	}
}

// TestAttack_PreHashIdentifierConfusion: id distinguishes "raw message"
// (0) from a specific pre-hash algorithm. A signature computed for one id
// must not verify under a different id, even with identical data bytes —
// otherwise an attacker could relabel a pre-hashed-message signature as a
// raw-message signature (or vice versa) to smuggle it into a different
// verification context. Run against both Falcon (original) and Falcon
// Precomputed.
func TestAttack_PreHashIdentifierConfusion(t *testing.T) {
	sk, vk, err := KeyGen(9, nil)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	data := make([]byte, 32) // valid length for a SHA-256 pre-hash
	for i := range data {
		data[i] = byte(i)
	}

	for _, variant := range signerVariants(t, sk) {
		t.Run(variant.name, func(t *testing.T) {
			sigRaw, err := variant.sign(nil, DOMAIN_NONE, 0, data)
			if err != nil {
				t.Fatalf("sign as raw failed: %v", err)
			}
			if Verify(vk, DOMAIN_NONE, crypto.SHA256, data, sigRaw) {
				t.Fatal("VULNERABLE: raw-message signature verified as a SHA-256 pre-hash signature")
			}

			sigHashed, err := variant.sign(nil, DOMAIN_NONE, crypto.SHA256, data)
			if err != nil {
				t.Fatalf("sign as SHA-256 pre-hash failed: %v", err)
			}
			if Verify(vk, DOMAIN_NONE, 0, data, sigHashed) {
				t.Fatal("VULNERABLE: SHA-256 pre-hash signature verified as a raw-message signature")
			}

			t.Log("PROTECTED: pre-hash identifier mismatch correctly rejected")
		})
	}
}

// TestAttack_BitFlipTampering: a single flipped bit in either the
// signature or the message must invalidate verification. Run against both
// Falcon (original) and Falcon Precomputed so the two are directly
// comparable — pkg/fndsa/sign_precomputed_test.go's
// TestPrecomputedSignRejectsTampering already covers the precomputed path
// alone; this test adds the original-signer counterpart under identical
// conditions.
// Reference: Fouque et al., "Falcon: Fast-Fourier Lattice-based Compact
// Signatures over NTRU" (NIST PQC Round 3 submission) — Verify algorithm,
// https://falcon-sign.info/falcon.pdf; EUF-CMA (Goldwasser/Micali/Rivest,
// 1988) — a scheme where an attacker can flip signature/message bits and
// still pass verification trivially fails unforgeability.
func TestAttack_BitFlipTampering(t *testing.T) {
	sk, vk, err := KeyGen(9, nil)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	data := []byte("bit-flip tamper-check message")

	for _, variant := range signerVariants(t, sk) {
		t.Run(variant.name, func(t *testing.T) {
			sig, err := variant.sign(nil, DOMAIN_NONE, 0, data)
			if err != nil {
				t.Fatalf("sign failed: %v", err)
			}

			tamperedSig := bytes.Clone(sig)
			tamperedSig[len(tamperedSig)/2] ^= 0x80
			if Verify(vk, DOMAIN_NONE, 0, data, tamperedSig) {
				t.Fatal("VULNERABLE: tampered signature verified")
			}

			tamperedData := bytes.Clone(data)
			tamperedData[0] ^= 0x01
			if Verify(vk, DOMAIN_NONE, 0, tamperedData, sig) {
				t.Fatal("VULNERABLE: tampered message verified")
			}

			t.Log("PROTECTED: bit-flip signature/message tampering rejected")
		})
	}
}

// TestAttack_TruncatedSignatureRejected: a truncated or overlong signature
// buffer must fail decoding rather than being accepted or panicking. Falcon
// signatures use a fixed-format compressed encoding; any length deviation
// is malformed input, not a valid forgery attempt, and Verify must fail
// closed. Run against both Falcon (original) and Falcon Precomputed, since
// both produce the same compact signature encoding.
func TestAttack_TruncatedSignatureRejected(t *testing.T) {
	sk, vk, err := KeyGen(9, nil)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	data := []byte("truncation test message")

	for _, variant := range signerVariants(t, sk) {
		t.Run(variant.name, func(t *testing.T) {
			sig, err := variant.sign(nil, DOMAIN_NONE, 0, data)
			if err != nil {
				t.Fatalf("sign failed: %v", err)
			}

			cases := []struct {
				name string
				sig  []byte
			}{
				{"empty", nil},
				{"single byte", sig[:1]},
				{"half length", sig[:len(sig)/2]},
				{"one byte short", sig[:len(sig)-1]},
				{"one byte over (zero-padded)", append(bytes.Clone(sig), 0x00)},
			}

			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					if Verify(vk, DOMAIN_NONE, 0, data, tc.sig) {
						t.Fatalf("VULNERABLE: malformed signature (%s, len=%d) verified", tc.name, len(tc.sig))
					}
				})
			}
			t.Log("PROTECTED: malformed/truncated signature encodings rejected")
		})
	}
}
