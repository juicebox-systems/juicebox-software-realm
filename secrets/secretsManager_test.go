package secrets

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/juicebox-systems/juicebox-software-realm/types"
	"github.com/stretchr/testify/assert"
)

func TestParseKid(t *testing.T) {
	// Valid input
	token := &jwt.Token{
		Header: map[string]interface{}{
			"kid": "juicebox:456",
		},
	}

	tenantName, version, err := ParseKid(token)
	assert.NoError(t, err)
	expectedTenantName := "juicebox"
	expectedVersion := uint64(456)
	assert.Equal(t, expectedTenantName, *tenantName)
	assert.Equal(t, expectedVersion, *version)

	// "kid" is not a string
	token = &jwt.Token{
		Header: map[string]interface{}{"kid": 5},
	}

	tenantName, version, err = ParseKid(token)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt kid is not a string")
	assert.Nil(t, tenantName)
	assert.Nil(t, version)

	// "kid" must only contain alphanumeric characters
	token = &jwt.Token{
		Header: map[string]interface{}{"kid": "abc123//*:2"},
	}

	tenantName, version, err = ParseKid(token)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt kid contains non-alphanumeric tenant name")
	assert.Nil(t, tenantName)
	assert.Nil(t, version)

	// "kid" can also have "test-" prefix
	token = &jwt.Token{
		Header: map[string]interface{}{"kid": "test-abc123:456"},
	}

	tenantName, version, err = ParseKid(token)
	assert.NoError(t, err)
	expectedTenantName = "test-abc123"
	expectedVersion = uint64(456)
	assert.Equal(t, expectedTenantName, *tenantName)
	assert.Equal(t, expectedVersion, *version)

	// Missing "kid" field in the token header
	token = &jwt.Token{
		Header: map[string]interface{}{},
	}

	tenantName, version, err = ParseKid(token)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt missing kid")
	assert.Nil(t, tenantName)
	assert.Nil(t, version)

	// Invalid "kid" field format
	token = &jwt.Token{
		Header: map[string]interface{}{
			"kid": "invalid-format",
		},
	}

	tenantName, version, err = ParseKid(token)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt kid incorrectly formatted")
	assert.Nil(t, tenantName)
	assert.Nil(t, version)

	// Invalid version number in the "kid" field
	token = &jwt.Token{
		Header: map[string]interface{}{
			"kid": "example123:invalid-version:whoa",
		},
	}

	tenantName, version, err = ParseKid(token)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt kid contained invalid version")
	assert.Nil(t, tenantName)
	assert.Nil(t, version)
}

func TestParseAuthKey(t *testing.T) {
	// no json encoding as HS256
	key := []byte("artemis")
	parsedKey, err := ParseAuthKey(key, "HS256")
	assert.NoError(t, err)
	assert.Equal(t, parsedKey, key)

	// HS256+UTF8
	key, err = json.Marshal(types.AuthKeyJSON{
		Data:      "artemis",
		Encoding:  types.UTF8,
		Algorithm: types.HS256,
	})
	assert.NoError(t, err)
	parsedKey, err = ParseAuthKey(key, "HS256")
	assert.NoError(t, err)
	assert.Equal(t, parsedKey, []byte("artemis"))

	// HS256+Hex
	key, err = json.Marshal(types.AuthKeyJSON{
		Data:      hex.EncodeToString([]byte("apollo")),
		Encoding:  types.Hex,
		Algorithm: types.HS256,
	})
	assert.NoError(t, err)
	parsedKey, err = ParseAuthKey(key, "HS256")
	assert.NoError(t, err)
	assert.Equal(t, parsedKey, []byte("apollo"))

	// EdDSA with valid key
	keyHex := "302a300506032b65700321009fc1ac7fad6f56d29ddde3c30c96e1a9bbce6c92286fb7ee72d6995bb2e1e443"
	keyBytes, err := hex.DecodeString(keyHex)
	assert.NoError(t, err)
	pubKey, err := x509.ParsePKIXPublicKey(keyBytes)
	assert.NoError(t, err)
	key, err = json.Marshal(types.AuthKeyJSON{
		Data:      keyHex,
		Encoding:  types.Hex,
		Algorithm: types.EdDSA,
	})
	assert.NoError(t, err)
	parsedKey, err = ParseAuthKey(key, "EdDSA")
	assert.NoError(t, err)
	assert.Equal(t, parsedKey, pubKey)

	// EdDSA with invalid key
	key, err = json.Marshal(types.AuthKeyJSON{
		Data:      hex.EncodeToString([]byte("apollo")),
		Encoding:  types.Hex,
		Algorithm: types.EdDSA,
	})
	assert.NoError(t, err)
	parsedKey, err = ParseAuthKey(key, "EdDSA")
	assert.Error(t, err, "wat")
	assert.Nil(t, parsedKey)

	// RS256 with valid key
	keyHex = "30820222300d06092a864886f70d01010105000382020f003082020a0282020100b0b7a7a0ecc25d2d1ea01c3113b008524ac2d974c427930763263a5968fe0ee3a30075bd10b148c0c7ecd51e4fd04fa6c17110789c664585b2f77f5bb162a5de9486f5301049843b72bc33237dfb249741b2c85630241c2021bf88a76bad0a0587c16dc2f0d70435f77e002f4cc47df14a4a5fa1a22f1865eef75214effeae172f2cfd388e315816f9d660e9c22328ec41712bd89497de8c2f890a86972db4a0e7996b71e1d2ba93056d4eb7dc87be7773ad1736669edbffbb69b3644c00d3485fbb03d34aa56b4382744a655f38584efe5f463c914da8203a81385639601a086349985b5c031caf9a1fb082be2230dcdac71b198f362dfbac33d0d79ee3113fd071d1532cc91fbb77817e9e2be9119945656a099a832af382278914a0e2a7216afd4dd6383e890e44a9bb3a2bfca41eadf3dc56d2a0024624eb1469613218232df0b96ace00f37c333a7c1d423930a318dfeb00e3dcd39214d3451b84c72a8e97895a0f1f68d3bfb191e64be2ca812e44c5e30ff97bbe998bd82f3b1b5d25607083ab4e1d1a3d9a8e9eadf78aad04be90cc938f6cec2a2d686dab7037fe432461b4eafac67c366501d6c03e2bde0071809e9241d48b290c2878be9aa75f6e6f3201428e56210e33bce6b713113b2ad111811edeb2ca2dd76a6445745a0b1427b19b9c0f6a9ec3f6010e358774bbe6d41696eb265d537d38dbb30c27f971c7910203010001"
	keyBytes, err = hex.DecodeString(keyHex)
	assert.NoError(t, err)
	pubKey, err = x509.ParsePKIXPublicKey(keyBytes)
	assert.NoError(t, err)
	key, err = json.Marshal(types.AuthKeyJSON{
		Data:      keyHex,
		Encoding:  types.Hex,
		Algorithm: types.RS256,
	})
	assert.NoError(t, err)
	parsedKey, err = ParseAuthKey(key, "RS256")
	assert.NoError(t, err)
	assert.Equal(t, parsedKey, pubKey)

	// RS256 with invalid key
	key, err = json.Marshal(types.AuthKeyJSON{
		Data:      hex.EncodeToString([]byte("apollo")),
		Encoding:  types.Hex,
		Algorithm: types.RS256,
	})
	assert.NoError(t, err)
	parsedKey, err = ParseAuthKey(key, "RS256")
	assert.Error(t, err, "wat")
	assert.Nil(t, parsedKey)

	// Bad Encoding
	key, err = json.Marshal(types.AuthKeyJSON{
		Data:      hex.EncodeToString([]byte("apollo")),
		Encoding:  "ASCII",
		Algorithm: types.EdDSA,
	})
	assert.NoError(t, err)
	parsedKey, err = ParseAuthKey(key, "EdDSA")
	assert.EqualError(t, err, "invalid signing key encoding=ASCII")
	assert.Nil(t, parsedKey)

	// Alg mismatch
	key, err = json.Marshal(types.AuthKeyJSON{
		Data:      hex.EncodeToString([]byte("apollo")),
		Encoding:  types.Hex,
		Algorithm: types.HS256,
	})
	assert.NoError(t, err)
	parsedKey, err = ParseAuthKey(key, "EdDSA")
	assert.EqualError(t, err, "unexpected jwt signing method=EdDSA")
	assert.Nil(t, parsedKey)

	// Bad Hex
	key, err = json.Marshal(types.AuthKeyJSON{
		Data:      "apollo",
		Encoding:  types.Hex,
		Algorithm: types.EdDSA,
	})
	assert.NoError(t, err)
	parsedKey, err = ParseAuthKey(key, "EdDSA")
	assert.EqualError(t, err, "invalid signing key hex")
	assert.Nil(t, parsedKey)
}
