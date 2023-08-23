package records

import (
	"encoding/hex"
	"errors"
	"reflect"

	"github.com/fxamacker/cbor/v2"
	"github.com/juicebox-systems/juicebox-software-realm/types"
	"golang.org/x/crypto/blake2s"
)

type UserRecordID string

func CreateUserRecordID(tenantName string, userID string) (UserRecordID, error) {
	type UserRecordIDSerializer struct {
		TenantName string `cbor:"tenant_name"`
		UserID     string `cbor:"user_id"`
	}

	data, err := cbor.Marshal(UserRecordIDSerializer{tenantName, userID})
	if err != nil {
		return "", err
	}

	hash := blake2s.Sum256(data)

	return UserRecordID(hex.EncodeToString(hash[:])), nil
}

type UserRecord struct {
	// oneof Registered, NotRegistered, NoGuesses
	RegistrationState interface{} `cbor:"registration_state"`
}

type Registered struct {
	Version                   types.RegistrationVersion       `cbor:"version"`
	OprfPrivateKey            types.OprfPrivateKey            `cbor:"oprf_private_key"`
	OprfSignedPublicKey       types.OprfSignedPublicKey       `cbor:"oprf_signed_public_key"`
	UnlockKeyCommitment       types.UnlockKeyCommitment       `cbor:"unlock_key_commitment"`
	UnlockKeyTag              types.UnlockKeyTag              `cbor:"unlock_key_tag"`
	EncryptionKeyScalarShare  types.EncryptionKeyScalarShare  `cbor:"encryption_key_scalar_share"`
	EncryptedSecret           types.EncryptedSecret           `cbor:"encrypted_secret"`
	EncryptedSecretCommitment types.EncryptedSecretCommitment `cbor:"encrypted_secret_commitment"`
	GuessCount                uint16                          `cbor:"guess_count"`
	Policy                    types.Policy                    `cbor:"policy"`
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
