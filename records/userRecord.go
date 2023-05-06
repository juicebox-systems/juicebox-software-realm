package records

import (
	"reflect"

	"github.com/fxamacker/cbor/v2"
	"github.com/juicebox-software-realm/types"
)

type UserRecordId string

type UserRecord struct {
	RegistrationState interface{} `cbor:"registration_state"`
	// TODO: Audit logs?
}

type Registered struct {
	OprfKey        types.OprfKey
	Salt           types.Salt
	MaskedTgkShare types.MaskedTgkShare
	SecretShare    types.SecretShare
	UnlockTag      types.UnlockTag
	GuessCount     uint16
	Policy         types.Policy
}

type NoGuesses struct{}
type NotRegistered struct{}

func (ur *UserRecord) MarshalCBOR() ([]byte, error) {
	var m interface{}

	name := reflect.TypeOf(ur.RegistrationState).Name()

	m = map[string]interface{}{name: ur.RegistrationState}

	data, error := cbor.Marshal(m)
	if error != nil {
		return nil, error
	}

	return data, nil
}

func (ur *UserRecord) UnmarshalCBOR(data []byte) error {
	var m interface{}
	error := cbor.Unmarshal(data, &m)
	if error != nil {
		return error
	}

	for key, value := range m.(map[interface{}]interface{}) {
		cborData, error := cbor.Marshal(value)
		if error != nil {
			return error
		}

		switch key {
		case "Registered":
			var registered Registered
			error = cbor.Unmarshal(cborData, &registered)
			if error != nil {
				return error
			}
			ur.RegistrationState = registered
		case "NoGuesses":
			ur.RegistrationState = NoGuesses{}
		case "NotRegistered":
			ur.RegistrationState = NotRegistered{}
		}
	}

	return nil
}
