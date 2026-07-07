package fndsa

import (
	"crypto"
	"crypto/rand"
	"errors"
	"io"
	"unsafe"

	sha3 "golang.org/x/crypto/sha3"
)

// PrecomputedSigner stores key-dependent values so multiple signatures
// can reuse the same FFT basis and LDL tree.
type PrecomputedSigner struct {
	logn     uint
	hashedVK [64]byte
	b00      []f64
	b01      []f64
	b10      []f64
	b11      []f64
	tree     *ldlTree
}

type ldlTree struct {
	logn  uint
	l10   []f64
	left  *ldlTree
	right *ldlTree
	leaf  f64
}

// LogN returns the logarithmic degree of the key bound to this signer.
func (ps *PrecomputedSigner) LogN() uint {
	if ps == nil {
		return 0
	}
	return ps.logn
}

// PersistentBytes estimates resident expanded-key material held by this signer.
// It includes struct headers and backing arrays for FFT basis plus LDL tree.
func (ps *PrecomputedSigner) PersistentBytes() int {
	if ps == nil {
		return 0
	}
	return int(unsafe.Sizeof(*ps)) +
		f64SliceBytes(ps.b00) +
		f64SliceBytes(ps.b01) +
		f64SliceBytes(ps.b10) +
		f64SliceBytes(ps.b11) +
		ldlTreePersistentBytes(ps.tree)
}

func ldlTreePersistentBytes(tree *ldlTree) int {
	if tree == nil {
		return 0
	}
	return int(unsafe.Sizeof(*tree)) +
		f64SliceBytes(tree.l10) +
		ldlTreePersistentBytes(tree.left) +
		ldlTreePersistentBytes(tree.right)
}

func f64SliceBytes(values []f64) int {
	return len(values) * int(unsafe.Sizeof(f64_ZERO))
}

// NewPrecomputedSigner creates a signer for standard degrees (512 and 1024).
func NewPrecomputedSigner(skey []byte) (*PrecomputedSigner, error) {
	return newPrecomputedSignerInner(9, 10, skey)
}

// NewPrecomputedSignerWeak creates a signer for non-standard weak degrees
// (4 to 256), meant for research and tests.
func NewPrecomputedSignerWeak(skey []byte) (*PrecomputedSigner, error) {
	return newPrecomputedSignerInner(2, 8, skey)
}

func newPrecomputedSignerInner(lognMin uint, lognMax uint,
	skey []byte) (*PrecomputedSigner, error) {

	// Get degree from key.
	if len(skey) == 0 {
		return nil, errors.New("Invalid private key")
	}
	head1 := skey[0]
	if (head1 & 0xF0) != 0x50 {
		return nil, errors.New("Invalid private key")
	}
	logn := uint(head1 & 0x0F)
	if logn < lognMin || logn > lognMax {
		return nil, errors.New("Invalid private key")
	}
	if len(skey) != SigningKeySize(logn) {
		return nil, errors.New("Invalid private key")
	}

	// Decode key, yielding f, g and F.
	n := 1 << logn
	f := make([]int8, n)
	g := make([]int8, n)
	F := make([]int8, n)
	off := 1
	j, err := trim_i8_decode(logn, skey[off:], f, nbits_fg(logn))
	if err != nil {
		return nil, err
	}
	off += j
	j, err = trim_i8_decode(logn, skey[off:], g, nbits_fg(logn))
	if err != nil {
		return nil, err
	}
	off += j
	_, err = trim_i8_decode(logn, skey[off:], F, 8)
	if err != nil {
		return nil, err
	}

	// Recompute G and the public polynomial h.
	G := make([]int8, n)
	t0 := make([]uint16, n)
	t1 := make([]uint16, n)
	mqpoly_small_to_int(logn, g, t0)
	mqpoly_small_to_int(logn, f, t1)
	mqpoly_int_to_ntt(logn, t0)
	mqpoly_int_to_ntt(logn, t1)
	if !mqpoly_div_ntt(logn, t0, t1) {
		return nil, errors.New("Invalid signing key (f not invertible)")
	}
	mqpoly_small_to_int(logn, F, t1)
	mqpoly_int_to_ntt(logn, t1)
	mqpoly_mul_ntt(logn, t1, t0)
	mqpoly_ntt_to_int(logn, t1)
	if !mqpoly_int_to_small(logn, t1, G) {
		return nil, errors.New("Invalid signing key (G is out-of-range)")
	}

	// Compute hash of verifying key.
	mqpoly_ntt_to_int(logn, t0)
	mqpoly_int_to_ext(logn, t0)
	vrfyKey := make([]byte, VerifyingKeySize(logn))
	vrfyKey[0] = byte(0x00 + logn)
	_ = modq_encode(logn, t0, vrfyKey[1:])
	var hashedVK [64]byte
	sh := sha3.NewShake256()
	sh.Write(vrfyKey)
	sh.Read(hashedVK[:])

	// Precompute FFT basis.
	basis := make([]f64, n*4)
	basis_to_FFT(logn, f, g, F, G, basis)
	b00 := append([]f64(nil), basis[:n]...)
	b01 := append([]f64(nil), basis[n:n*2]...)
	b10 := append([]f64(nil), basis[n*2:n*3]...)
	b11 := append([]f64(nil), basis[n*3:n*4]...)

	// Precompute LDL tree from the Gram matrix.
	gram := append([]f64(nil), basis...)
	g00 := gram[:n]
	g01 := gram[n : n*2]
	g11 := gram[n*2 : n*3]
	fpoly_gram_fft(logn, g00, g01, g11, gram[n*3:n*4])
	tree := buildLDLTree(logn, logn, g00, g01, g11)

	ps := &PrecomputedSigner{
		logn:     logn,
		hashedVK: hashedVK,
		b00:      b00,
		b01:      b01,
		b10:      b10,
		b11:      b11,
		tree:     tree,
	}
	if !ps.isValid() {
		return nil, errors.New("Invalid precomputed signer")
	}
	return ps, nil
}

// Sign signs data with the precomputed key material.
func (ps *PrecomputedSigner) Sign(rng io.Reader,
	ctx DomainContext, id crypto.Hash, data []byte) ([]byte, error) {

	if !ps.isReadyForSign() {
		return nil, errors.New("Invalid precomputed signer")
	}
	var seed [40]byte
	if rng == nil {
		rng = rand.Reader
	}
	_, err := io.ReadFull(rng, seed[:])
	if err != nil {
		return nil, err
	}
	return ps.signSeeded(seed[:], ctx, id, data)
}

func (ps *PrecomputedSigner) signSeeded(seed []byte,
	ctx DomainContext, id crypto.Hash, data []byte) ([]byte, error) {

	n := 1 << ps.logn
	tmp_i16 := make([]int16, n)
	tmp_u16 := make([]uint16, n)
	tmp_f64 := make([]f64, n*8)
	sig := make([]byte, SignatureSize(ps.logn))
	err := sign_core_precomputed(ps, ctx, id, data, seed, sig,
		tmp_i16, tmp_u16, tmp_f64)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (ps *PrecomputedSigner) isValid() bool {
	if ps == nil || ps.logn < 1 || ps.logn >= uint(len(inv_sigma)) {
		return false
	}
	n := 1 << ps.logn
	return len(ps.b00) == n &&
		len(ps.b01) == n &&
		len(ps.b10) == n &&
		len(ps.b11) == n &&
		validateLDLTree(ps.logn, ps.tree)
}

func (ps *PrecomputedSigner) isReadyForSign() bool {
	if ps == nil || ps.logn < 1 || ps.logn >= uint(len(inv_sigma)) {
		return false
	}
	n := 1 << ps.logn
	return len(ps.b00) == n &&
		len(ps.b01) == n &&
		len(ps.b10) == n &&
		len(ps.b11) == n &&
		ps.tree != nil &&
		ps.tree.logn == ps.logn
}

func validateLDLTree(logn uint, tree *ldlTree) bool {
	if tree == nil || tree.logn != logn {
		return false
	}
	if logn == 0 {
		return tree.l10 == nil && tree.left == nil && tree.right == nil && tree.leaf != f64_ZERO
	}
	n := 1 << logn
	return len(tree.l10) == n &&
		validateLDLTree(logn-1, tree.left) &&
		validateLDLTree(logn-1, tree.right)
}

func sign_core_precomputed(ps *PrecomputedSigner,
	ctx DomainContext, id crypto.Hash, data []byte,
	seed []byte, sig []byte, tmp_i16 []int16, tmp_u16 []uint16, tmp_f64 []f64) error {

	logn := ps.logn
	n := 1 << logn
	sh := sha3.NewShake256()
	hm := tmp_u16
	s2 := tmp_i16
	sig = sig[:SignatureSize(logn)]

	for counter := 0; ; counter++ {
		// Generate nonce and sub-seed.
		sh.Reset()
		sh.Write(seed)
		var cbuf [4]byte
		cbuf[0] = uint8(counter)
		cbuf[1] = uint8(counter >> 8)
		cbuf[2] = uint8(counter >> 16)
		cbuf[3] = uint8(counter >> 24)
		sh.Write(cbuf[:])
		var nonce [40]byte
		var subseed [56]byte
		sh.Read(nonce[:])
		sh.Read(subseed[:])

		// Hash message to point.
		err := hash_to_point(logn, nonce[:], ps.hashedVK[:], ctx, id, data, hm)
		if err != nil {
			return err
		}

		// Sample vector in Fourier space with precomputed LDL tree.
		ss := newSampler(logn, subseed[:])
		t0 := tmp_f64[:n]
		t1 := tmp_f64[n : n*2]
		fpoly_apply_basis(logn, t0, t1, ps.b01, ps.b11, hm)
		ss.ffsamp_fft_precomputed(t0, t1, ps.tree, tmp_f64[n*2:])

		// Map sampled vector back to lattice point.
		tx := tmp_f64[n*2 : n*3]
		ty := tmp_f64[n*3 : n*4]
		copy(tx, t0)
		copy(ty, t1)
		fpoly_mul_fft(logn, tx, ps.b00)
		fpoly_mul_fft(logn, ty, ps.b10)
		fpoly_add(logn, tx, ty)
		copy(ty, t0)
		fpoly_mul_fft(logn, ty, ps.b01)
		copy(t0, tx)
		fpoly_mul_fft(logn, t1, ps.b11)
		fpoly_add(logn, t1, ty)
		fpoly_iFFT(logn, t0)
		fpoly_iFFT(logn, t1)

		// Compute norm and candidate signature.
		sqn := uint32(0)
		ng := uint32(0)
		for i := 0; i < n; i++ {
			zu := hm[i] - uint16(f64_rint(t0[i]))
			z := int32(int16(zu))
			sqn += uint32(z * z)
			ng |= sqn
		}
		for i := 0; i < n; i++ {
			zu := -uint16(f64_rint(t1[i]))
			z := int32(int16(zu))
			sqn += uint32(z * z)
			ng |= sqn
			s2[i] = int16(z)
		}
		sqn |= uint32(int32(ng) >> 31)
		if !mqpoly_sqnorm_is_acceptable(logn, sqn) {
			continue
		}

		// Encode signature.
		if comp_encode(logn, s2, sig[41:]) {
			sig[0] = byte(0x30 + logn)
			copy(sig[1:41], nonce[:])
			return nil
		}
	}
}

func buildLDLTree(rootLogn uint, logn uint,
	g00 []f64, g01 []f64, g11 []f64) *ldlTree {

	if logn == 1 {
		g00_re := g00[0]
		g01_re := g01[0]
		g01_im := g01[1]
		g11_re := g11[0]
		inv_g00_re := f64_inv(g00_re)
		mu_re := f64_mul(g01_re, inv_g00_re)
		mu_im := f64_mul(g01_im, inv_g00_re)
		zo_re := f64_add(f64_mul(mu_re, g01_re), f64_mul(mu_im, g01_im))
		d11_re := f64_sub(g11_re, zo_re)
		node := &ldlTree{
			logn: 1,
			l10:  []f64{mu_re, f64_neg(mu_im)},
		}
		node.left = &ldlTree{
			logn: 0,
			leaf: f64_mul(f64_sqrt(g00_re), inv_sigma[rootLogn]),
		}
		node.right = &ldlTree{
			logn: 0,
			leaf: f64_mul(f64_sqrt(d11_re), inv_sigma[rootLogn]),
		}
		return node
	}

	n := 1 << logn
	hn := n >> 1
	fpoly_LDL_fft(logn, g00, g01, g11)
	node := &ldlTree{
		logn: logn,
		l10:  append([]f64(nil), g01[:n]...),
	}

	w0 := make([]f64, hn)
	w1 := make([]f64, hn)

	fpoly_split_selfadj_fft(logn, w0, w1, g00)
	left00 := append([]f64(nil), w0...)
	left01 := append([]f64(nil), w1...)

	fpoly_split_selfadj_fft(logn, w0, w1, g11)
	right00 := append([]f64(nil), w0...)
	right01 := append([]f64(nil), w1...)

	left11 := append([]f64(nil), left00...)
	right11 := append([]f64(nil), right00...)

	node.left = buildLDLTree(rootLogn, logn-1, left00, left01, left11)
	node.right = buildLDLTree(rootLogn, logn-1, right00, right01, right11)
	return node
}

func (s *sampler) ffsamp_fft_precomputed(
	t0 []f64, t1 []f64, tree *ldlTree, tmp []f64) {

	s.ffsamp_fft_precomputed_inner(tree, t0, t1, tmp)
}

func (s *sampler) ffsamp_fft_precomputed_inner(
	tree *ldlTree, t0 []f64, t1 []f64, tmp []f64) {

	if tree.logn == 1 {
		w0 := t1[0]
		w1 := t1[1]
		y0 := f64_of_i32(s.next(w0, tree.right.leaf))
		y1 := f64_of_i32(s.next(w1, tree.right.leaf))
		a_re := f64_sub(w0, y0)
		a_im := f64_sub(w1, y1)
		b_re, b_im := flc_mul(a_re, a_im, tree.l10[0], tree.l10[1])
		x0 := f64_add(t0[0], b_re)
		x1 := f64_add(t0[1], b_im)
		t1[0] = y0
		t1[1] = y1
		t0[0] = f64_of_i32(s.next(x0, tree.left.leaf))
		t0[1] = f64_of_i32(s.next(x1, tree.left.leaf))
		return
	}

	logn := tree.logn
	n := 1 << logn
	hn := n >> 1

	w0 := tmp[:hn]
	w1 := tmp[hn:n]
	w2 := tmp[n:]
	fpoly_split_fft(logn, w0, w1, t1)
	s.ffsamp_fft_precomputed_inner(tree.right, w0, w1, w2)
	z1 := tmp[n*2 : n*3]
	fpoly_merge_fft(logn, z1, w0, w1)

	l10 := tmp[:n]
	w := tmp[n : n*2]
	copy(w, t1[:n])
	fpoly_sub(logn, w, z1)
	copy(t1[:n], z1)
	copy(l10, tree.l10)
	fpoly_mul_fft(logn, l10, w)
	fpoly_add(logn, t0, l10)

	w0 = tmp[:hn]
	w1 = tmp[hn:n]
	w2 = tmp[n:]
	fpoly_split_fft(logn, w0, w1, t0)
	s.ffsamp_fft_precomputed_inner(tree.left, w0, w1, w2)
	fpoly_merge_fft(logn, t0, w0, w1)
}
