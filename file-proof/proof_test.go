package proof

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	com "github.com/memoio/contractsv2/common"
	"github.com/memoio/contractsv2/go_contracts/erc"
	inst "github.com/memoio/contractsv2/go_contracts/instance"
)

var globalPrivateKeys []string
var vkBytes = []byte{165, 28, 62, 86, 129, 157, 190, 133, 129, 43, 4, 192, 136, 168, 15, 150, 24, 52, 27, 59, 30, 100, 178, 37, 106, 218, 52, 104, 137, 196, 161, 154, 127, 23, 155, 85, 200, 199, 59, 31, 108, 6, 140, 237, 215, 135, 3, 99, 18, 28, 155, 16, 224, 117, 133, 185, 238, 241, 13, 199, 209, 16, 225, 148, 121, 151, 1, 113, 238, 170, 129, 121, 64, 107, 3, 32, 178, 115, 90, 112, 43, 3, 42, 44, 176, 14, 163, 113, 233, 228, 194, 201, 41, 171, 80, 182}

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

	info.Submitter = crypto.PubkeyToAddress(sk.PublicKey)
	info.Receiver = crypto.PubkeyToAddress(sk.PublicKey)
	srs, err := kzg.NewSRS(1000000, big.NewInt(985))
	if err != nil {
		t.Error(err.Error())
		return
	}
	t.Log(srs.Vk.G2[1].Bytes())

	var sks [5]string
	copy(sks[:], globalPrivateKeys[1:])

	err = proofInstance.AlterSetting(info, srs.Vk.G2[1], sks)
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

	// vk, err := proofInstance.GetVK()
	// if err != nil {
	// 	t.Error(err.Error())
	// 	return
	// }
	// t.Log(vk.Bytes())
}

func TestBalance(t *testing.T) {
	instanceAddr, endpoint := com.GetInsEndPointByChain("dev")

	client, err := ethclient.DialContext(context.TODO(), endpoint)
	if err != nil {
		t.Fatal(err.Error())
	}

	instanceIns, err := inst.NewInstance(instanceAddr, client)
	if err != nil {
		t.Fatal(err.Error())
	}

	tokenAddr, err := instanceIns.Instances(&bind.CallOpts{}, com.TypeERC20)
	if err != nil {
		t.Fatal(err.Error())
	}

	tokenIns, err := erc.NewERC20(tokenAddr, client)
	if err != nil {
		t.Fatal(err.Error())
	}

	// balance, balanceErc20, err := getBalance(client, tokenIns, globalPrivateKeys[0])
	// if err != nil {
	// 	t.Fatal(err.Error())
	// }
	// t.Log(balance)
	// t.Log(balanceErc20)

	// sk1, err := crypto.HexToECDSA(globalPrivateKeys[1])
	// if err != nil {
	// 	t.Fatal(err.Error())
	// }
	// err = transferMemo(endpoint, client, tokenIns, globalPrivateKeys[0], crypto.PubkeyToAddress(sk1.PublicKey), big.NewInt(1000000000000000000))
	// if err != nil {
	// 	t.Fatal(err.Error())
	// }
	// err = transferEth(endpoint, client, globalPrivateKeys[0], crypto.PubkeyToAddress(sk1.PublicKey), big.NewInt(1000000000000000000))
	// if err != nil {
	// 	t.Fatal(err.Error())
	// }

	balance, balanceErc20, err := getBalance(client, tokenIns, globalPrivateKeys[1])
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Log(balance)
	t.Log(balanceErc20)
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

func getBalance(client *ethclient.Client, tokenIns *erc.ERC20, sk string) (*big.Int, *big.Int, error) {
	sk0, err := crypto.HexToECDSA(sk)
	if err != nil {
		return nil, nil, err
	}
	balance, err := client.BalanceAt(context.TODO(), crypto.PubkeyToAddress(sk0.PublicKey), nil)
	if err != nil {
		return nil, nil, err
	}

	balanceErc20, err := tokenIns.BalanceOf(&bind.CallOpts{}, crypto.PubkeyToAddress(sk0.PublicKey))
	if err != nil {
		return nil, nil, err
	}
	return balance, balanceErc20, nil
}

func transferMemo(endpoint string, client *ethclient.Client, tokenIns *erc.ERC20, fromSK string, to common.Address, amount *big.Int) error {
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		chainID = big.NewInt(985)
	}
	auth, err := com.MakeAuth(chainID, fromSK)
	if err != nil {
		return err
	}
	tx, err := tokenIns.Transfer(auth, to, amount)
	if err != nil {
		return err
	}
	return CheckTx(endpoint, tx.Hash(), "transfer memo")
}

func transferEth(endpoint string, client *ethclient.Client, fromSK string, to common.Address, amount *big.Int) error {
	privateKey, err := crypto.HexToECDSA(fromSK)
	if err != nil {
		return err
	}

	nonce, err := client.PendingNonceAt(context.Background(), crypto.PubkeyToAddress(privateKey.PublicKey))
	if err != nil {
		return err
	}

	gasLimit := uint64(21000) // in units
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return err
	}
	tx := types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, nil)

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		chainID = big.NewInt(985)
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		return err
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return err
	}

	return CheckTx(endpoint, signedTx.Hash(), "transfer eth")
}
