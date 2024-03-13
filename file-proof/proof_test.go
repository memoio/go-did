package proof

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"math/big"
	"math/rand"
	"testing"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
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

func TestAddFile(t *testing.T) {
	filesize := 1024 * 127

	g1 := GenRandomG1()
	etag := ToSolidityG1(g1)

	start := big.NewInt(time.Now().Unix())            // start time of file storage
	end := new(big.Int).Add(start, big.NewInt(20*60)) // end  time of file storage

	userSk, err := crypto.HexToECDSA(globalPrivateKeys[1])
	if err != nil {
		t.Fatal(err)
	}
	proofIns, err := NewProofInstance(userSk, "dev")
	if err != nil {
		t.Fatal(err)
	}

	hash := proofIns.GetCredentialHash2(etag, uint64(filesize), start, end)
	t.Log(hash)
	credentical, err := com.Sign(hash, globalPrivateKeys[0])
	if err != nil {
		t.Fatal(err)
	}

	err = proofIns.AddFile(g1, uint64(filesize), start, end, credentical)
	if err != nil {
		t.Fatal(err)
	}
}

func GenRandomG1() bls12381.G1Affine {
	var res bls12381.G1Affine
	res.X.SetRandom()
	res.Y.SetRandom()
	return res
}

func TestAlterSettingInfo(t *testing.T) {
	sk, err := crypto.HexToECDSA(globalPrivateKeys[0])
	if err != nil {
		t.Fatal(err)
	}

	proofInstance, err := NewProofInstance(sk, "dev")
	if err != nil {
		t.Fatal(err)
	}

	info, err := proofInstance.GetSettingInfo()
	if err != nil {
		t.Fatal(err)
	}

	data, err := json.MarshalIndent(info, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))

	info.Interval = 60
	info.Period = 60
	info.RespondTime = 30
	info.Submitter = crypto.PubkeyToAddress(sk.PublicKey)
	info.Receiver = crypto.PubkeyToAddress(sk.PublicKey)
	srs, err := kzg.NewSRS(1024*4, big.NewInt(985))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(srs.Vk.G2[1].Bytes())

	var sks [5]string
	copy(sks[:], globalPrivateKeys[1:])

	hash, err := proofInstance.GetAlterSettingInfoHash(info, srs.Vk.G2[1])
	if err != nil {
		t.Fatal(err)
	}
	err = proofInstance.AlterSetting(info, srs.Vk.G2[1], com.GetSigns(hash, sks))
	if err != nil {
		t.Fatal(err)
	}

	info, err = proofInstance.GetSettingInfo()
	if err != nil {
		t.Fatal(err)
	}

	data, err = json.MarshalIndent(info, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))

	vk, err := proofInstance.GetVK()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(vk.Bytes())
}

func TestSubmitProof(t *testing.T) {
	sk, err := crypto.HexToECDSA(globalPrivateKeys[0])
	if err != nil {
		t.Fatal(err)
	}

	proofIns, err := NewProofInstance(sk, "dev")
	if err != nil {
		t.Fatal(err)
	}

	lastRnd, _, last, err := proofIns.GetVerifyInfo()
	if err != nil {
		t.Fatal(err)
	}

	setting, err := proofIns.GetSettingInfo()
	if err != nil {
		t.Fatal(err)
	}

	wait := calculateWatingTime(last.Int64(), int64(setting.Interval), int64(setting.Period))
	t.Log(wait)
	time.Sleep(wait)

	err = proofIns.GenerateRnd()
	if err != nil {
		t.Fatal(err)
	}

	nowRnd, _, _, err := proofIns.GetVerifyInfo()
	if err != nil {
		t.Fatal(err)
	}

	t.Log(lastRnd, nowRnd)

	data := GenRandomBytes(128)

	poly := split(data)
	srs, err := kzg.NewSRS(1024*4, big.NewInt(985))
	if err != nil {
		t.Fatal(err)
	}

	commit, err := kzg.Commit(poly, srs.Pk)
	if err != nil {
		t.Fatal(err)
	}

	kzgProof, err := kzg.Open(poly, nowRnd, srs.Pk)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(kzgProof.H, kzgProof.ClaimedValue)

	err = proofIns.SubmitAggregationProof(nowRnd, commit, kzgProof)
	if err != nil {
		t.Fatal(err)
	}
}

func GenRandomBytes(len int) []byte {
	res := make([]byte, len)
	for i := 0; i < len; i += 7 {
		val := rand.Int63()
		for j := 0; i+j < len && j < 7; j++ {
			res[i+j] = byte(val)
			val >>= 8
		}
	}
	return res
}

func calculateWatingTime(last, interval, period int64) time.Duration {
	challengeCycleSeconds := interval + period
	now := time.Now().Unix()
	duration := now - last
	over := duration % challengeCycleSeconds
	var waitingSeconds int64 = 0
	if over < interval {
		waitingSeconds = interval - over
	}

	return time.Duration(waitingSeconds) * time.Second
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

	balance, balanceErc20, err := getBalance(client, tokenIns, globalPrivateKeys[0])
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Log(balance)
	t.Log(balanceErc20)

	balance, balanceErc20, err = getBalance(client, tokenIns, globalPrivateKeys[1])
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Log(balance)
	t.Log(balanceErc20)
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
	return CheckTx(endpoint, auth.From, tx, "transfer memo")
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

	return CheckTx(endpoint, crypto.PubkeyToAddress(privateKey.PublicKey), signedTx, "transfer eth")
}

const ShardingLen = 127

func Pad127(in []byte, res []fr.Element) {
	if len(in) != 127 {
		if len(in) > 127 {
			in = in[:127]
		} else {
			padding := make([]byte, 127-len(in))
			in = append(in, padding...)
		}
	}

	tmp := make([]byte, 32)
	copy(tmp[:31], in[:31])

	t := in[31] >> 6
	tmp[31] = in[31] & 0x3f
	res[0].SetBytes(tmp)

	var v byte
	for i := 32; i < 64; i++ {
		v = in[i]
		tmp[i-32] = (v << 2) | t
		t = v >> 6
	}
	t = v >> 4
	tmp[31] &= 0x3f
	res[1].SetBytes(tmp)

	for i := 64; i < 96; i++ {
		v = in[i]
		tmp[i-64] = (v << 4) | t
		t = v >> 4
	}
	t = v >> 2
	tmp[31] &= 0x3f
	res[2].SetBytes(tmp)

	for i := 96; i < 127; i++ {
		v = in[i]
		tmp[i-96] = (v << 6) | t
		t = v >> 2
	}
	tmp[31] = t & 0x3f
	res[3].SetBytes(tmp)
}

func split(data []byte) []fr.Element {
	num := (len(data)-1)/ShardingLen + 1

	atom := make([]fr.Element, num*4)

	padding := make([]byte, ShardingLen*num-len(data))
	data = append(data, padding...)

	for i := 0; i < num; i++ {
		Pad127(data[ShardingLen*i:ShardingLen*(i+1)], atom[4*i:4*i+4])
	}

	return atom
}
