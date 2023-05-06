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

	data, error := cbor.Marshal(m)
	if error != nil {
		return nil, error
	}

	return data, nil
}

func isEmptyInterface(s interface{}) bool {
	v := reflect.ValueOf(s)
	if v.Kind() != reflect.Struct {
		return false
	}

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if !field.IsZero() {
			return false
		}
	}

	return true
}
