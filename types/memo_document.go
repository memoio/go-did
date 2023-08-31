package types

import (
	"encoding/hex"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/memoio/did-solidity/go-contracts/proxy"
)

type MemoDIDDocument struct {
	Context              string               `json:"@context"`
	ID                   MemoDID              `json:"id"`
	VerificationMethod   []VerificationMethod `json:"verifycationMethod"`
	Authentication       []MemoDIDUrl         `json:"authentication,omitempty"`
	AssertionMethod      []MemoDIDUrl         `json:"assertionMethod,omitempty"`
	CapabilityDelegation []MemoDIDUrl         `json:"capabilityDelegation,omitempty"`
	Recovery             []MemoDIDUrl         `json:"recovery,omitempty"`
}

type PublicKey struct {
	Type         string `json:"type"`
	PublicKeyHex string `json:"publicKeyHex"`
}

type VerificationMethod struct {
	ID         MemoDIDUrl `json:"id"`
	Controller MemoDID    `json:"controller"`
	PublicKey
}

func FromSolityData(did MemoDID, methodIndex int64, method *proxy.IAccountDidPublicKey) (*VerificationMethod, error) {
	if method.Controller == "" {
		method.Controller = "did:memo:0000000000000000000000000000000000000000000000000000000000000000"
	} else {
		method.Controller = "did:memo:" + method.Controller
	}

	controller, err := ParseMemoDID(method.Controller)
	if err != nil {
		return nil, err
	}

	didUrl, err := did.DIDUrl(methodIndex)
	if err != nil {
		return nil, err
	}

	publicKeyHex := hexutil.Encode(method.PubKeyData)
	return &VerificationMethod{
		ID:         didUrl,
		Controller: *controller,
		PublicKey: PublicKey{
			Type:         method.MethodType,
			PublicKeyHex: publicKeyHex,
		},
	}, nil
}

func ToSolidityData(method *VerificationMethod) (*proxy.IAccountDidPublicKey, error) {
	publicKeyData, err := hexutil.Decode(method.PublicKeyHex)
	if err != nil {
		return nil, err
	}
	return &proxy.IAccountDidPublicKey{
		Controller: method.Controller.String(),
		MethodType: method.Type,
		PubKeyData: publicKeyData,
	}, nil
}

func (v PublicKey) VerifySignature(sig []byte, message ...[]byte) (bool, error) {
	switch v.Type {
	case "EcdsaSecp256k1VerificationKey2019":
		hash := crypto.Keccak256(message...)

		pubKey, err := crypto.SigToPub(hash, sig)
		if err != nil {
			return false, err
		}

		if v.PublicKeyHex != hexutil.Encode(crypto.CompressPubkey(pubKey)) {
			return false, nil
		}
	default:
		return false, errors.New("unsupport type")
	}
	return true, nil
}

func PublicKeyToAddress(pk PublicKey) (common.Address, error) {
	var address common.Address
	switch pk.Type {
	case "EcdsaSecp256k1VerificationKey2019":
		pubkey, err := hex.DecodeString(pk.PublicKeyHex)
		if err != nil {
			return common.Address{}, err
		}
		publicKey, err := crypto.DecompressPubkey(pubkey)
		if err != nil {
			return common.Address{}, err
		}
		address = crypto.PubkeyToAddress(*publicKey)
	default:
		return common.Address{}, errors.New("unsupport type")
	}
	return address, nil
}
