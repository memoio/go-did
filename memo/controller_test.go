package memo

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"reflect"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/memoio/go-did/types"
	"golang.org/x/xerrors"
)

var globalPrivateKeys []string

func init() {
	content, err := ioutil.ReadFile("../key.json")
	if err != nil {
		log.Fatal(err.Error())
	}

	err = json.Unmarshal(content, &globalPrivateKeys)
	if err != nil {
		log.Fatal(err.Error())
	}

	log.Println(globalPrivateKeys)

}

// var address1 string = "0xe89971bfeEA7381d47fE608d676dfb5440F0fD2E"
// var address2 string = "0x7C0491aE63e3816F96B777340b1571feA7bB21dE"
// var address3 string = "0xc0FF8898729d543c197Fb8b8ef7EE2f39024e1e8"
// var address4 string = "0x53F76F77DeC24D601ad3001114C9a35EfD4A5F5F"
// var address5 string = "0xC44F1bccDb80F266b727c5B3f2839AA3a2FEf1d1"

func ToPublicKey(privateKeyHex string) (string, error) {
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return "", err
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", xerrors.Errorf("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	return hex.EncodeToString(crypto.CompressPubkey(publicKeyECDSA)), nil
}

func ToPublicKeys(privateKeyHex []string) ([]*ecdsa.PrivateKey, []string, error) {
	var sks []*ecdsa.PrivateKey
	var pks []string
	for _, sk := range privateKeyHex {
		publicKey, err := ToPublicKey(sk)
		if err != nil {
			return nil, nil, err
		}

		privateKey, err := crypto.HexToECDSA(sk)
		if err != nil {
			return nil, nil, err
		}

		sks = append(sks, privateKey)
		pks = append(pks, publicKey)
	}

	return sks, pks, nil
}

func TestGetPK(t *testing.T) {
	_, pks, _ := ToPublicKeys(globalPrivateKeys)
	t.Log(pks)
}

func genVerificationMethod(did *types.MemoDID, methodIndex int64, controller *types.MemoDID, vtype, publicKeyHex string) (types.VerificationMethod, error) {
	if controller == nil {
		controller, _ = types.ParseMemoDID("did:memo:0000000000000000000000000000000000000000000000000000000000000000")
	}

	didUrl, err := did.DIDUrl(methodIndex)
	if err != nil {
		return types.VerificationMethod{}, err
	}

	if publicKeyHex[:2] != "0x" {
		publicKeyHex = "0x" + publicKeyHex
	}

	return types.VerificationMethod{
		ID:         didUrl,
		Controller: *controller,
		PublicKey: types.PublicKey{
			Type:         vtype,
			PublicKeyHex: publicKeyHex,
		},
	}, nil
}

// test creat, read, update and delete
func TestBasic(t *testing.T) {
	sks, pks, err := ToPublicKeys(globalPrivateKeys)
	if err != nil {
		t.Error(err.Error())
		return
	}

	privateKey := sks[0]

	masterKey := pks[0]
	pk1 := pks[1]
	pk2 := pks[2]
	// pk3 := pks[3]

	d := &types.MemoDIDDocument{}

	controller, err := NewMemoDIDController(privateKey, "dev")
	if err != nil {
		t.Error(err.Error())
		return
	}

	resolver, err := NewMemoDIDResolver("dev")
	if err != nil {
		t.Error(err.Error())
		return
	}

	did := controller.DID()
	t.Log(did)

	// register did(masterKey)
	err = controller.RegisterDID()
	if err != nil {
		t.Error(err.Error())
		return
	}

	document, err := resolver.Resolve(did.String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	verificationMethod, err := genVerificationMethod(did, 0, nil, "EcdsaSecp256k1VerificationKey2019", masterKey)
	if err != nil {
		t.Error(err.Error())
		return
	}

	d.Context = DefaultContext
	d.ID = *did
	d.VerificationMethod = append(d.VerificationMethod, verificationMethod)
	if !reflect.DeepEqual(document, d) {
		t.Error("Unexpect RegisterDID result")
		return
	}

	//
	// add verification method(key-1)
	err = controller.AddVerificationMethod("EcdsaSecp256k1VerificationKey2019", *did, pk1)
	if err != nil {
		t.Error(err.Error())
		return
	}

	document, err = resolver.Resolve(did.String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	verificationMethod, err = genVerificationMethod(did, 1, did, "EcdsaSecp256k1VerificationKey2019", pk1)
	if err != nil {
		t.Error(err.Error())
		return
	}
	d.VerificationMethod = append(d.VerificationMethod, verificationMethod)
	if !reflect.DeepEqual(document, d) {
		t.Error("Unexpect RegisterDID result")
		return
	}

	//
	// add authentication(key-1)
	err = controller.AddRelationShip(types.Authentication, document.VerificationMethod[0].ID, 0)
	if err != nil {
		t.Error(err.Error())
		return
	}

	document, err = resolver.Resolve(did.String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	d.Authentication = append(d.Authentication, d.VerificationMethod[0].ID)
	if !reflect.DeepEqual(document, d) {
		t.Error("Unexpect RegisterDID result")
		return
	}

	//
	// add verification method(key-2)
	err = controller.AddVerificationMethod("EcdsaSecp256k1VerificationKey2019", *did, pk2)
	if err != nil {
		t.Error(err.Error())
		return
	}

	document, err = resolver.Resolve(did.String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	verificationMethod, err = genVerificationMethod(did, 2, did, "EcdsaSecp256k1VerificationKey2019", pk2)
	if err != nil {
		t.Error(err.Error())
		return
	}
	d.VerificationMethod = append(d.VerificationMethod, verificationMethod)
	if !reflect.DeepEqual(document, d) {
		t.Error("Unexpect result")
		return
	}

	//
	// add assertion method(masterKey)
	err = controller.AddRelationShip(types.AssertionMethod, document.VerificationMethod[0].ID, 0)
	if err != nil {
		t.Error(err.Error())
		return
	}

	document, err = resolver.Resolve(did.String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	d.AssertionMethod = append(d.AssertionMethod, d.VerificationMethod[0].ID)
	if !reflect.DeepEqual(document, d) {
		t.Error("Unexpect result")
		return
	}

	//
	// add delegation(key-1, key-2)
	err = controller.AddRelationShip(types.CapabilityDelegation, document.VerificationMethod[1].ID, 7*24*int64(time.Hour.Seconds()))
	if err != nil {
		t.Error(err.Error())
		return
	}

	err = controller.AddRelationShip(types.CapabilityDelegation, document.VerificationMethod[2].ID, int64(time.Minute.Seconds()))
	if err != nil {
		t.Error(err.Error())
		return
	}

	document, err = resolver.Resolve(did.String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	d.CapabilityDelegation = append(d.CapabilityDelegation, d.VerificationMethod[1].ID)
	d.CapabilityDelegation = append(d.CapabilityDelegation, d.VerificationMethod[2].ID)
	if !reflect.DeepEqual(document, d) {
		t.Error("Unexpect result")
		return
	}

	//
	// add recovery(masterKey, key-1, key-2)
	err = controller.AddRelationShip(types.Recovery, document.VerificationMethod[0].ID, 0)
	if err != nil {
		t.Error(err.Error())
		return
	}

	err = controller.AddRelationShip(types.Recovery, document.VerificationMethod[1].ID, 0)
	if err != nil {
		t.Error(err.Error())
		return
	}

	err = controller.AddRelationShip(types.Recovery, document.VerificationMethod[2].ID, 0)
	if err != nil {
		t.Error(err.Error())
		return
	}

	document, err = resolver.Resolve(did.String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	d.Recovery = append(d.Recovery, d.VerificationMethod[0].ID)
	d.Recovery = append(d.Recovery, d.VerificationMethod[1].ID)
	d.Recovery = append(d.Recovery, d.VerificationMethod[2].ID)

	if !reflect.DeepEqual(document, d) {
		t.Error("Unexpect result")
		return
	}

	//
	// delegation(key-2) expires automatically
	time.Sleep(time.Minute)

	document, err = resolver.Resolve(did.String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	for i, delegation := range d.CapabilityDelegation {
		if delegation.String() == d.VerificationMethod[2].ID.String() {
			d.CapabilityDelegation = append(d.CapabilityDelegation[:i], d.CapabilityDelegation[i+1:]...)
			break
		}
	}
	if !reflect.DeepEqual(document, d) {
		t.Error("Unexpect result")
		return
	}

	// deactivate recovery(key-1)
	err = controller.DeactivateRelationShip(types.Recovery, document.VerificationMethod[1].ID)
	if err != nil {
		t.Error(err.Error())
		return
	}

	document, err = resolver.Resolve(did.String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	for i, recovery := range d.Recovery {
		if recovery.String() == d.VerificationMethod[1].ID.String() {
			d.Recovery = append(d.Recovery[:i], d.Recovery[i+1:]...)
			break
		}
	}
	if !reflect.DeepEqual(document, d) {
		t.Error("Unexpect result")
		return
	}

	//
	// dactivate verification method(key-2), also dactivate recovery(key-2).
	err = controller.DeactivateVerificationMethod(document.VerificationMethod[2].ID)
	if err != nil {
		t.Error(err.Error())
		return
	}

	document, err = resolver.Resolve(did.String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	d.VerificationMethod = d.VerificationMethod[:2]
	d.Recovery = d.Recovery[:1]
	if !reflect.DeepEqual(document, d) {
		t.Error("Unexpect result")
		return
	}

	data, _ := json.MarshalIndent(document, " ", "\t")
	t.Log(string(data))
	data, _ = json.MarshalIndent(d, " ", "\t")
	t.Log(string(data))

	remainUrl := d.Recovery[0]

	// dactivate did
	err = controller.DeactivateDID()
	if err != nil {
		t.Error(err.Error())
		return
	}

	document, err = resolver.Resolve(did.String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	d = &types.MemoDIDDocument{}
	if !reflect.DeepEqual(document, d) {
		t.Error("Unexpect result")
		return
	}

	// Trying to update dactivated did
	err = controller.AddVerificationMethod("EcdsaSecp256k1VerificationKey2019", *did, pk1)
	if err == nil {
		t.Error("There should report an error when trying to update dactivated did")
		return
	}

	err = controller.AddRelationShip(types.Authentication, remainUrl, 0)
	if err == nil {
		t.Error("There should report an error when trying to update dactivated did")
		return
	}

	err = controller.AddRelationShip(types.AssertionMethod, remainUrl, 0)
	if err == nil {
		t.Error("There should report an error when trying to update dactivated did")
		return
	}

	err = controller.AddRelationShip(types.CapabilityDelegation, remainUrl, 0)
	if err == nil {
		t.Error("There should report an error when trying to update dactivated did")
		return
	}

	err = controller.AddRelationShip(types.Recovery, remainUrl, 0)
	if err == nil {
		t.Error("There should report an error when trying to update dactivated did")
		return
	}
}

func TestResolve(t *testing.T) {
	resolver, err := NewMemoDIDResolver("dev")
	if err != nil {
		t.Error(err.Error())
		return
	}

	start := time.Now()
	document, err := resolver.Resolve("did:memo:d687daa192ffa26373395872191e8502cc41fbfbf27dc07d3da3a35de57c2d96")
	if err != nil {
		t.Error(err.Error())
		return
	}
	t.Log(time.Since(start).Seconds())

	documentBytes, err := json.MarshalIndent(document, "", "\t")
	if err != nil {
		t.Error(err.Error())
		return
	}

	fmt.Println(string(documentBytes))
}

func TestDerefrence(t *testing.T) {
	resolver, err := NewMemoDIDResolver("dev")
	if err != nil {
		t.Error(err.Error())
		return
	}

	publicKey, err := resolver.Dereference("did:memo:d687daa192ffa26373395872191e8502cc41fbfbf27dc07d3da3a35de57c2d96#masterKey")
	if err != nil {
		t.Error(err.Error())
		return
	}

	t.Log(publicKey)
}
