package types

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/xerrors"
)

func CreatSimpleDID(privateKeyHex string) (string, *MemoDID, error) {
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", nil, err
	}
	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return "", nil, err
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", nil, xerrors.Errorf("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	publicKeyHex := hex.EncodeToString(crypto.CompressPubkey(publicKeyECDSA))
	id := hex.EncodeToString(crypto.Keccak256(crypto.CompressPubkey(publicKeyECDSA), []byte("hello")))

	return publicKeyHex, &MemoDID{
		Method:      "memo",
		Identifier:  id,
		Identifiers: []string{id},
	}, nil
}

func TestMarshalMemoDocument(t *testing.T) {
	privateKey := "f9729aef404b8c13d06cf888376b04fd17581b9c308f9b4b16c020736ae89cd4"
	publicKeyHex, did, err := CreatSimpleDID(privateKey)
	if err != nil {
		t.Errorf("Can't Create did: %s", err.Error())
		return
	}

	methodID, err := ParseMemoDIDUrl(did.String() + "#masterKey")
	if err != nil {
		t.Errorf("Can't Parse did url: %s", err.Error())
		return
	}
	masterKey := VerificationMethod{
		ID:         *methodID,
		Controller: *did,
		PublicKey: PublicKey{
			Type:         "EcdsaSecp256k1VerificationKey2019",
			PublicKeyHex: publicKeyHex,
		},
	}
	document := &MemoDIDDocument{
		ID:                 *did,
		VerificationMethod: []VerificationMethod{masterKey},
		Authentication:     []MemoDIDUrl{masterKey.ID},
		AssertionMethod:    []MemoDIDUrl{masterKey.ID},
	}

	data, err := json.MarshalIndent(document, "", "\t")
	if err != nil {
		t.Errorf("Can't Marshal did document: %s", err.Error())
		return
	}

	t.Log(string(data))

	var documentResult MemoDIDDocument
	err = json.Unmarshal(data, &documentResult)
	if err != nil {
		t.Errorf("Can't Unmarshal did document: %s", err.Error())
		return
	}
}

func TestMarshalMfileDocument(t *testing.T) {
	document := MfileDIDDocument{
		Context: "https://www.w3.org/ns/did/v1",
		ID: MfileDID{
			Method:     "mfile",
			Identifier: "bafkreiaay2fxn7gplx6a2i47djwfrelwwrd7wcd6ih5ssspzjm3gb3dxna",
		},
		Type: "public",
		Controller: MemoDID{
			Method:     "memo",
			Identifier: "ea69956cb2bae2a25e8126e52dab195ce32f08fa51618bd834d1e47d6498253f",
		},
	}

	data, err := json.MarshalIndent(document, "", "\t")
	if err != nil {
		t.Fatal(err.Error())
	}

	t.Log(string(data))
}
