# jwt-go (Tasktify fork)

This package is a fork of [`golang-jwt/jwt`](https://github.com/golang-jwt/jwt)
(a Go implementation of [JSON Web Tokens](https://datatracker.ietf.org/doc/html/rfc7519)),
extended for Tasktify with post-quantum signing methods — FN-DSA, ML-DSA, and
SLH-DSA — alongside the original HMAC, RSA, RSA-PSS, and ECDSA support.

## Usage

```go
import "github.com/ridwanmuh3/tasktify/pkg/jwt"
```

Signing and parsing work the same as upstream `golang-jwt/jwt`; see the
[upstream usage guide](https://golang-jwt.github.io/jwt/usage/create/) for
general examples. The FN-DSA signing methods added here are documented in
`fndsa_alg.go`, `fndsa_original.go`, and `fndsa_precomputed.go`.

## License

MIT, inherited from upstream `golang-jwt/jwt`. See [`LICENSE`](./LICENSE).
