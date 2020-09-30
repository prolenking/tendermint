package types

import (
	"github.com/tendermint/tendermint/crypto/ed25519"
	cryptoenc "github.com/tendermint/tendermint/crypto/encoding"
)

func NewValidatorUpdate(pk []byte, power int64) ValidatorUpdate {
	pke := ed25519.PubKey(pk)
	pkp, err := cryptoenc.PubKeyToProto(pke)
	if err != nil {
		panic(err)
	}

	return ValidatorUpdate{
		PubKey: pkp,
	}
}
