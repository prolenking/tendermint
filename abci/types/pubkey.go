package types

import (
	"github.com/tendermint/tendermint/crypto/algo"
)

func NewValidatorUpdate(pubkey []byte, power int64) ValidatorUpdate {
	return ValidatorUpdate{
		// Address:
		PubKey: PubKey{
			Type: algo.GetPubKeyType(),
			Data: pubkey,
		},
		Power: power,
	}
}
