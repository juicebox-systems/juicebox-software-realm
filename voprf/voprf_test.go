package voprf

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/juicebox-software-realm/types"
	"github.com/stretchr/testify/assert"
)

type TestVector struct {
	Name   string
	Inputs struct {
		Input          string `json:"input"`
		PrivateKeySeed string `json:"private_key_seed"`
		BlindSeed      string `json:"blind_seed"`
		BetaTSeed      string `json:"beta_t_seed"`
	}
	Outputs struct {
		PrivateKey    string `json:"private_key"`
		PublicKey     string `json:"public_key"`
		InputHash     string `json:"input_hash"`
		Blind         string `json:"blind"`
		BlindedInput  string `json:"blinded_input"`
		BlindedOutput string `json:"blinded_output"`
		ProofC        string `json:"proof_c"`
		ProofBetaZ    string `json:"proof_beta_z"`
		Output        string `json:"proof_output"`
	}
}

func TestVectors(t *testing.T) {
	bytes, err := os.ReadFile("test_vectors.json")
	if err != nil {
		t.Fatalf("Failed to read test vectors: %v", err)
	}

	var testVectors []TestVector
	err = json.Unmarshal(bytes, &testVectors)
	if err != nil {
		t.Fatalf("Failed to parse test vectors from JSON: %v", err)
	}

	assert.GreaterOrEqual(t, len(testVectors), 3)

	for i := range testVectors {
		vector := &testVectors[i]
		t.Run(vector.Name, func(t *testing.T) {
			runTestVector(t, vector)
		})
	}
}

func runTestVector(t *testing.T, vector *TestVector) {
	privateKeyBytes, err := hex.DecodeString(vector.Outputs.PrivateKey)
	assert.Nil(t, err)
	privateKey := types.OprfPrivateKey(privateKeyBytes)

	publicKeyBytes, err := hex.DecodeString(vector.Outputs.PublicKey)
	assert.Nil(t, err)
	publicKey := types.OprfPublicKey(publicKeyBytes)

	blindedInputBytes, err := hex.DecodeString(vector.Outputs.BlindedInput)
	assert.Nil(t, err)
	blindedInput := types.OprfBlindedInput(blindedInputBytes)

	betaTSeed, err := hex.DecodeString(vector.Inputs.BetaTSeed)
	assert.Nil(t, err)
	rng := bytes.NewReader(betaTSeed)

	result, proof, err := BlindEvaluate(&privateKey, &publicKey, &blindedInput, rng)
	assert.Nil(t, err)
	assert.Equal(t, hex.EncodeToString(result[:]), vector.Outputs.BlindedOutput, "blinded_output")
	assert.Equal(t, hex.EncodeToString(proof.C[:]), vector.Outputs.ProofC, "proof.c")
	assert.Equal(t, hex.EncodeToString(proof.BetaZ[:]), vector.Outputs.ProofBetaZ, "proof.beta_z")
}
