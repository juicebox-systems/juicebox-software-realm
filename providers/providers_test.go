package providers

import (
	"testing"

	"github.com/juicebox-systems/juicebox-software-realm/types"
	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	// test invalid provider
	provider, err := Parse("invalid")
	assert.Error(t, err)
	assert.EqualError(t, err, "invalid ProviderName: invalid")
	assert.Negative(t, provider)

	// random case provider
	provider, err = Parse("gCp")
	assert.NoError(t, err)
	assert.Equal(t, provider, types.GCP)

	// upper case provider
	provider, err = Parse("AWS")
	assert.NoError(t, err)
	assert.Equal(t, provider, types.AWS)

	// lower case provider
	provider, err = Parse("mongo")
	assert.NoError(t, err)
	assert.Equal(t, provider, types.Mongo)
}
