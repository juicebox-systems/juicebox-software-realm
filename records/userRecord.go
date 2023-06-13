package records

import (
	"errors"
	"reflect"

	"github.com/fxamacker/cbor/v2"
	"github.com/juicebox-software-realm/types"
)

type UserRecordID string

type UserRecord struct {
	// oneof Registered, NotRegistered, NoGuesses
	RegistrationState interface{} `cbor:"registration_state"`
}

type Registered struct {
	OprfSeed             types.OprfSeed             `cbor:"oprf_seed"`
	Version              types.RegistrationVersion  `cbor:"version"`
	SaltShare            types.SaltShare            `cbor:"salt_share"`
	MaskedUnlockKeyShare types.MaskedUnlockKeyShare `cbor:"masked_unlock_key_share"`
	SecretShare          types.SecretShare          `cbor:"secret_share"`
	UnlockTag            types.UnlockTag            `cbor:"unlock_tag"`
	GuessCount           uint16                     `cbor:"guess_count"`
	Policy               types.Policy               `cbor:"policy"`
}

type NoGuesses struct{}
type NotRegistered struct{}

func DefaultUserRecord() UserRecord {
	return UserRecord{
		RegistrationState: NotRegistered{},
	}
}

func (ur *UserRecord) MarshalCBOR() ([]byte, error) {
	var m interface{}

	name := reflect.TypeOf(ur.RegistrationState).Name()

	m = map[string]interface{}{name: ur.RegistrationState}

	data, err := cbor.Marshal(m)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (ur *UserRecord) UnmarshalCBOR(data []byte) error {
	var m map[string]cbor.RawMessage
	err := cbor.Unmarshal(data, &m)
	if err != nil {
		return err
	}

	for key, value := range m {
		switch key {
		case "Registered":
			var registered Registered
			err = cbor.Unmarshal(value, &registered)
			if err != nil {
				return err
			}
			ur.RegistrationState = registered
		case "NoGuesses":
			ur.RegistrationState = NoGuesses{}
		case "NotRegistered":
			ur.RegistrationState = NotRegistered{}
		default:
			return errors.New("unexpected registration state")
		}
	}

	return nil
}
