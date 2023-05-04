package requests

import "github.com/fxamacker/cbor/v2"

type SecretsRequest struct {
	Payload interface{}
}

func (sr *SecretsRequest) UnmarshalCBOR(data []byte) error {
	var m interface{}
	err := cbor.Unmarshal(data, &m)
	if err != nil {
		return err
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
		for k, v := range t {
			cborData, err := cbor.Marshal(v)
			if err != nil {
				return err
			}

			switch k {
			case "Register2":
				var register2 Register2
				err = cbor.Unmarshal(cborData, &register2)
				if err != nil {
					return err
				}
				sr.Payload = register2
			case "Recover2":
				var recover2 Recover2
				err = cbor.Unmarshal(cborData, &recover2)
				if err != nil {
					return err
				}
				sr.Payload = recover2
			case "Recover3":
				var recover3 Recover3
				err = cbor.Unmarshal(cborData, &recover3)
				if err != nil {
					return err
				}
				sr.Payload = recover3
			}
		}
	}

	return nil
}
