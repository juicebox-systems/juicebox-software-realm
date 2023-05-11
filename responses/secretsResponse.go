package responses

import (
	"reflect"

	"github.com/fxamacker/cbor/v2"
)

type Status string

const (
	Ok            Status = "Ok"
	NotRegistered Status = "NotRegistered"
	BadUnlockTag  Status = "BadUnlockTag"
	NoGuesses     Status = "NoGuesses"
)

type SecretsResponse struct {
	Status  Status
	Payload interface{}
}

func (sr *SecretsResponse) MarshalCBOR() ([]byte, error) {
	var m interface{}

	name := reflect.TypeOf(sr.Payload).Name()

	if isEmptyInterface(sr.Payload) {
		m = map[string]interface{}{name: sr.Status}
	} else {
		m = map[string]interface{}{name: map[string]interface{}{string(sr.Status): sr.Payload}}
	}

	data, err := cbor.Marshal(m)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func isEmptyInterface(s interface{}) bool {
	if s == nil {
		return false
	}
	zero := reflect.Zero(reflect.TypeOf(s))
	return reflect.DeepEqual(zero.Interface(), s)
}
