package records

import "github.com/juicebox-software-realm/types"

type UserRecordId [32]byte

type UserRecord struct {
	RegistrationState interface{}
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
