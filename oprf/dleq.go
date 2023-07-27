package oprf

import (
	"crypto/sha512"
	"io"

	r255 "github.com/gtank/ristretto255"
	"github.com/juicebox-software-realm/types"
)

func generateProof(
	beta *r255.Scalar, // privateKey
	u *r255.Element, // blindedInput
	v *types.OprfPublicKey, // publicKey
	w *r255.Element, // blindedResult
	cryptoRng io.Reader,
) (*types.OprfProof, error) {
	var betaTSeed [64]byte
	_, err := cryptoRng.Read(betaTSeed[:])
	if err != nil {
		return nil, err
	}
	betaT := r255.NewScalar().FromUniformBytes(betaTSeed[:])

	vT := r255.NewElement().ScalarBaseMult(betaT)

	wT := r255.NewElement().ScalarMult(betaT, u)

	c := hashToChallenge(u, v, w, vT, wT)

	betaZ := r255.NewScalar().Add(betaT, r255.NewScalar().Multiply(beta, c))

	return &types.OprfProof{
		C:     [32]byte(c.Encode(nil)),
		BetaZ: [32]byte(betaZ.Encode(nil)),
	}, nil
}

func hashToChallenge(
	u *r255.Element, // blindedInput
	v *types.OprfPublicKey, // publicKey
	w *r255.Element, // blindedResult
	vT *r255.Element,
	wT *r255.Element,
) *r255.Scalar {
	h := []byte("Juicebox_DLEQ_2023_1;")
	h = u.Encode(h)
	h = append(h, v[:]...)
	h = w.Encode(h)
	h = vT.Encode(h)
	h = wT.Encode(h)

	hash := sha512.Sum512(h)
	return r255.NewScalar().FromUniformBytes(hash[:])
}
