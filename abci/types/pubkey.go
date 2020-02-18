package types

const (
	PubKeySm2     = "sm2"
)

func Sm2ValidatorUpdate(pubkey []byte, power int64) ValidatorUpdate {
	return ValidatorUpdate{
		// Address:
		PubKey: PubKey{
			Type: PubKeySm2,
			Data: pubkey,
		},
		Power: power,
	}
}
