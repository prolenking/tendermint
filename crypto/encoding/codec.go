package encoding

import (
	"fmt"
	"github.com/tendermint/tendermint/crypto/sm2"

	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/ed25519"
	pc "github.com/tendermint/tendermint/proto/tendermint/crypto"
)

// PubKeyToProto takes crypto.PubKey and transforms it to a protobuf Pubkey
func PubKeyToProto(k crypto.PubKey) (pc.PublicKey, error) {
	var kp pc.PublicKey
	switch k := k.(type) {
	case sm2.PubKeySm2:
		kp = pc.PublicKey{
			Sum: &pc.PublicKey_Sm2{
				Sm2: k[:],
			},
		}
	case ed25519.PubKey:
		kp = pc.PublicKey{
			Sum: &pc.PublicKey_Ed25519{
				Ed25519: k,
			},
		}
	default:
		return kp, fmt.Errorf("toproto: key type %v is not supported", k)
	}
	return kp, nil
}

// PubKeyFromProto takes a protobuf Pubkey and transforms it to a crypto.Pubkey
func PubKeyFromProto(k pc.PublicKey) (crypto.PubKey, error) {
	switch k := k.Sum.(type) {
	case *pc.PublicKey_Sm2:
		if len(k.Sm2) != sm2.PubKeySize {
			return nil, fmt.Errorf("invalid size for PubKeySm2. Got %d, expected %d",
				len(k.Sm2), sm2.PubKeySize)
		}
		pk := sm2.PubKeySm2{}
		copy(pk[:], k.Sm2)
		return pk, nil
	case *pc.PublicKey_Ed25519:
		if len(k.Ed25519) != ed25519.PubKeySize {
			return nil, fmt.Errorf("invalid size for PubKeyEd25519. Got %d, expected %d",
				len(k.Ed25519), ed25519.PubKeySize)
		}
		pk := make(ed25519.PubKey, ed25519.PubKeySize)
		copy(pk, k.Ed25519)
		return pk, nil
	default:
		return nil, fmt.Errorf("fromproto: key type %v is not supported", k)
	}
}
