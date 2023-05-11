package requests

import (
	"github.com/fxamacker/cbor/v2"
)

type SecretsRequest struct {
	Payload interface{}
}

func (sr *SecretsRequest) UnmarshalCBOR(data []byte) error {
	var s string
	err := cbor.Unmarshal(data, &s)
	if err == nil {
		switch s {
		case "Register1":
			sr.Payload = Register1{}
		case "Recover1":
			sr.Payload = Recover1{}
		case "Delete":
			sr.Payload = Delete{}
		}
	} else {
		var m map[string]cbor.RawMessage
		err = cbor.Unmarshal(data, &m)
		if err != nil {
			return err
		}

		for key, value := range m {
			switch key {
			case "Register2":
				var register2 Register2
				err = cbor.Unmarshal(value, &register2)
				if err != nil {
					return err
				}
				sr.Payload = register2
			case "Recover2":
				var recover2 Recover2
				err = cbor.Unmarshal(value, &recover2)
				if err != nil {
					return err
				}
				sr.Payload = recover2
			case "Recover3":
				var recover3 Recover3
				err = cbor.Unmarshal(value, &recover3)
				if err != nil {
					return err
				}
				sr.Payload = recover3
			}
		}
	}

	return nil
}
