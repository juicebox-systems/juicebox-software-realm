package oprf

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/juicebox-systems/juicebox-software-realm/types"
	"github.com/stretchr/testify/assert"
)

type TestVector struct {
	Name   string
	Inputs struct {
		Input              string `json:"input"`
		PrivateKeySeed     string `json:"private_key_seed"`
		BlindingFactorSeed string `json:"blinding_factor_seed"`
		BetaTSeed          string `json:"beta_t_seed"`
	}
	Outputs struct {
		PrivateKey     string `json:"private_key"`
		PublicKey      string `json:"public_key"`
		BlindingFactor string `json:"blinding_factor"`
		BlindedInput   string `json:"blinded_input"`
		BlindedOutput  string `json:"blinded_output"`
		ProofC         string `json:"proof_c"`
		ProofBetaZ     string `json:"proof_beta_z"`
		Output         string `json:"proof_output"`
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

func TestInsufficientEntropy(t *testing.T) {
	privateKeyBytes, err := hex.DecodeString("cca1a0304b113ec01cafa2545c0428497fd65a4924b4697033f5c19aaec2ac0a")
	assert.Nil(t, err)
	privateKey := types.OprfPrivateKey(privateKeyBytes)

	publicKeyBytes, err := hex.DecodeString("9e2bc4e246e540092324937ed33fd01caf0297137e35345c32ecf49e87e35056")
	assert.Nil(t, err)
	publicKey := types.OprfPublicKey(publicKeyBytes)

	blindedInputBytes, err := hex.DecodeString("a8767323a469385742eb85b73a3d51372f4e15d336f72567eb12d3410fa6815c")
	assert.Nil(t, err)
	blindedInput := types.OprfBlindedInput(blindedInputBytes)

	// This is intentionally 63 bytes instead of the required 64 bytes.
	betaTSeed, err := hex.DecodeString("e3338a037375a11171895585f670ea0a2a195d99f60c0d75a649ed565364b3976eb10bce2dd4c8eed0ffc0597de08e879142590faa87cee2be4d9241909077")
	assert.Nil(t, err)
	rng := bytes.NewReader(betaTSeed)

	_, _, err = BlindEvaluate(&privateKey, &publicKey, &blindedInput, rng)
	assert.EqualError(t, err, "unexpected EOF")
}
