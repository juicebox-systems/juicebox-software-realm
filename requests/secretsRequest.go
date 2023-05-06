package requests

import (
	"github.com/fxamacker/cbor/v2"
)

type SecretsRequest struct {
	Payload interface{}
}

func (sr *SecretsRequest) UnmarshalCBOR(data []byte) error {
	var m interface{}
	error := cbor.Unmarshal(data, &m)
	if error != nil {
		return error
	}

	switch t := m.(type) {
	case string:
		switch t {
		case "Register1":
			sr.Payload = Register1{}
		case "Recover1":
			sr.Payload = Recover1{}
		case "Delete":
			sr.Payload = Delete{}
		}

	case map[interface{}]interface{}:
		for key, value := range t {
			cborData, error := cbor.Marshal(value)
			if error != nil {
				return error
			}

			switch key {
			case "Register2":
				var register2 Register2
				error = cbor.Unmarshal(cborData, &register2)
				if error != nil {
					return error
				}
				sr.Payload = register2
			case "Recover2":
				var recover2 Recover2
				error = cbor.Unmarshal(cborData, &recover2)
				if error != nil {
					return error
				}
				sr.Payload = recover2
			case "Recover3":
				var recover3 Recover3
				error = cbor.Unmarshal(cborData, &recover3)
				if error != nil {
					return error
				}
				sr.Payload = recover3
			}
		}
	}

	return nil
}
