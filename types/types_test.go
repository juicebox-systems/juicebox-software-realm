package types

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHttpError(t *testing.T) {
	assert.Nil(t, NewHTTPError(500, nil))

	// Should do nothing if 'err' is already a HttpError
	e := NewHTTPError(500, errors.New("boom"))
	assert.Same(t, e, NewHTTPError(400, e))

	// Should preserve the status code from the wrapped error
	wrapped := NewHTTPError(300, fmt.Errorf("failed to blah: %w", e))
	assert.Equal(t, 500, wrapped.Code)
	assert.EqualError(t, wrapped, "failed to blah: boom")

	// Even if its multiple levels deep
	first := NewHTTPError(418, errors.New("not a teapot"))
	wrappedOne := fmt.Errorf("failed: %w", first)
	wrappedTwo := fmt.Errorf("nested: %w", wrappedOne)
	wrappedThree := fmt.Errorf("nested more: %w", wrappedTwo)
	e = NewHTTPError(500, wrappedThree)
	assert.Equal(t, 418, e.Code)
	assert.EqualError(t, e, "nested more: nested: failed: not a teapot")
}
