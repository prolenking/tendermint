package sm2

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/tjfoc/gmsm/sm2"

	amino "github.com/tendermint/go-amino"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/tmhash"
)

var _ crypto.PrivKey = PrivKeySm2{}
var _ crypto.PubKey = PubKeySm2{}

const (
	PrivKeyAminoName = "tendermint/PrivKeySm2"
	PubKeyAminoName  = "tendermint/PubKeySm2"
)

var cdc = amino.NewCodec()

func init() {
	cdc.RegisterInterface((*crypto.PubKey)(nil), nil)
	cdc.RegisterConcrete(PubKeySm2{}, PubKeyAminoName, nil)

	cdc.RegisterInterface((*crypto.PrivKey)(nil), nil)
	cdc.RegisterConcrete(PrivKeySm2{}, PrivKeyAminoName, nil)
}

// --------------------------------------------------------

type PrivKeySm2 struct {
	sm2.PrivateKey
}

func (privKey PrivKeySm2) Bytes() []byte {
	return cdc.MustMarshalBinaryBare(privKey)
}

func (privKey PrivKeySm2) Sign(msg []byte) ([]byte, error) {
	r, s, err := sm2.Sign(&privKey.PrivateKey, msg)
	if err != nil {
		panic(err)
	}

	return sm2.SignDigitToSignData(r, s)
}

func (privKey PrivKeySm2) PubKey() crypto.PubKey {
	return PubKeySm2{privKey.PrivateKey.PublicKey}
}

func (privKey PrivKeySm2) Equals(other crypto.PrivKey) bool {
	if otherSm2, ok := other.(PrivKeySm2); ok {
		// TODO
		return subtle.ConstantTimeCompare(privKey.Bytes(), otherSm2.Bytes()) == 1
	}

	return false
}

func GenPrivKey() PrivKeySm2 {
	return genPrivKey(crypto.CReader())
}

func genPrivKey(rand io.Reader) PrivKeySm2 {
	seed := make([]byte, 32)
	if _, err := io.ReadFull(rand, seed); err != nil {
		panic(err)
	}

	privKey, err := sm2.GenerateKey()
	if err != nil {
		panic(err)
	}

	return PrivKeySm2{*privKey}
}

// --------------------------------------------------------

type PubKeySm2 struct {
	sm2.PublicKey
}

func (pubKey PubKeySm2) Address() crypto.Address {
	return crypto.Address(tmhash.SumTruncated(sm2.Compress(&pubKey.PublicKey)))
}

func (pubKey PubKeySm2) Bytes() []byte {
	return cdc.MustMarshalBinaryBare(pubKey)
}

func (pubKey PubKeySm2) VerifyBytes(msg []byte, sig []byte) bool {
	r, s, err := sm2.SignDataToSignDigit(sig)
	if err != nil {
		panic(err)
	}

	return sm2.Verify(&pubKey.PublicKey, msg, r, s)
}

func (pubKey PubKeySm2) String() string {
	return fmt.Sprintf("PubKeySm2{%X}", sm2.Compress(&pubKey.PublicKey))
}

func (pubKey PubKeySm2) Equals(other crypto.PubKey) bool {
	// TODO
	if otherSm2, ok := other.(PubKeySm2); ok {
		return bytes.Equal(pubKey.Bytes(), otherSm2.Bytes())
	} else {
		return false
	}
}
