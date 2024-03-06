package proof

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/ethereum/go-ethereum/crypto"
)

var globalPrivateKeys []string

func init() {
	content, err := ioutil.ReadFile("../proof-keys.json")
	if err != nil {
		log.Fatal(err.Error())
	}

	err = json.Unmarshal(content, &globalPrivateKeys)
	if err != nil {
		log.Fatal(err.Error())
	}

	log.Println(globalPrivateKeys)
}

func TestAlterSettingInfo(t *testing.T) {
	sk, err := crypto.HexToECDSA(globalPrivateKeys[0])
	if err != nil {
		t.Error(err.Error())
		return
	}

	proofInstance, err := NewProofInstance(sk, "dev")
	if err != nil {
		t.Error(err.Error())
		return
	}

	info, err := proofInstance.GetSettingInfo()
	if err != nil {
		t.Error(err.Error())
		return
	}

	data, err := json.MarshalIndent(info, "", "\t")
	if err != nil {
		t.Error(err.Error())
		return
	}
	t.Log(string(data))

	info.Price = 3
	_, _, _, vk := bls12381.Generators()

	var sks [5]string
	copy(sks[:], globalPrivateKeys[1:])

	err = proofInstance.AlterSetting(info, vk, sks)
	if err != nil {
		log.Fatal(err)
	}

	info, err = proofInstance.GetSettingInfo()
	if err != nil {
		t.Error(err.Error())
		return
	}

	data, err = json.MarshalIndent(info, "", "\t")
	if err != nil {
		t.Error(err.Error())
		return
	}
	t.Log(string(data))
}

func TestGetVerifyInfo(t *testing.T) {
	sk, err := crypto.HexToECDSA(globalPrivateKeys[0])
	if err != nil {
		t.Error(err.Error())
		return
	}

	proofInstance, err := NewProofInstance(sk, "dev")
	if err != nil {
		t.Error(err.Error())
		return
	}

	_, last, err := proofInstance.GetVerifyInfo()
	if err != nil {
		t.Error(err.Error())
		return
	}
	t.Log(last)
}
