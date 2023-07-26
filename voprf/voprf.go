// Package voprf implements the server side of a VOPRF.
//
// The VOPRF is based on 2HashDH and a Chaum-Pedersen DLEQ proof. See the Rust
// implementation in the Juicebox SDK for more details.
package voprf

import (
	"io"

	r255 "github.com/gtank/ristretto255"
	"github.com/juicebox-software-realm/types"
)

// BlindEvaluate runs the VOPRF evaluation on the server.
//
// It returns errors from decoding inputs and reading the given RNG.
func BlindEvaluate(
	privateKey *types.OprfPrivateKey,
	publicKey *types.OprfPublicKey,
	blindedInput *types.OprfBlindedInput,
	cryptoRng io.Reader,
) (*types.OprfBlindedResult, *types.OprfProof, error) {
	privateKeyScalar := r255.NewScalar()
	err := privateKeyScalar.Decode(privateKey[:])
	if err != nil {
		return nil, nil, err
	}

	blindedInputPoint := r255.NewElement()
	err = blindedInputPoint.Decode(blindedInput[:])
	if err != nil {
		return nil, nil, err
	}

	blindedResultPoint := r255.NewElement().ScalarMult(privateKeyScalar, blindedInputPoint)
	blindedResult := types.OprfBlindedResult(blindedResultPoint.Encode(nil))

	proof, err := generateProof(
		privateKeyScalar,   // beta
		blindedInputPoint,  // u
		publicKey,          // v
		blindedResultPoint, // w
		cryptoRng,
	)
	if err != nil {
		return nil, nil, err
	}

	return &blindedResult, proof, nil
}
