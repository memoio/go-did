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

func init() {
	content, err := ioutil.ReadFile("../proof-keys.json")
	if err != nil {
		log.Fatal(err.Error())
	}

	err = json.Unmarshal(content, &globalPrivateKeys)
	if err != nil {
		log.Fatal(err.Error())
	}

	for _, PrivateKey := range globalPrivateKeys {
		sk, err := crypto.HexToECDSA(PrivateKey)
		if err != nil {
			log.Fatal(err.Error())
		}

		log.Println(crypto.PubkeyToAddress(sk.PublicKey))
	}
}

func TestAddFile(t *testing.T) {
	filesize := 1024 * 127

	g1 := GenRandomG1()
	// etag := ToSolidityG1(g1)

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

	hash := proofIns.GetCredentialHash(crypto.PubkeyToAddress(userSk.PublicKey), g1, uint64(filesize), start, end)
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

	info.Interval = 480
	info.Period = 120
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

func TestSelectFiles(t *testing.T) {
	sk, err := crypto.HexToECDSA(globalPrivateKeys[0])
	if err != nil {
		t.Log(err)
	}

	proofIns, err := NewProofInstance(sk, "dev")
	if err != nil {
		t.Log(err)
	}

	rnd, err := proofIns.GetRndRawBytes()
	if err != nil {
		t.Log(err)
	}

	challengeInfo, err := proofIns.GetChallengeInfo()
	if err != nil {
		t.Log(err)
	}
	length := challengeInfo.ChalLength.Int64()

	// big.NewInt(0).SetBytes()

	var random *big.Int = big.NewInt(0).SetBytes(rnd[:])
	random = new(big.Int).Mod(random, big.NewInt(length))
	startIndex := new(big.Int).Div(random, big.NewInt(2))
	t.Log(length)
	t.Log(startIndex)

	sum, commit, err := proofIns.GetFileCommit(startIndex)
	if err != nil {
		t.Log(err)
	}
	t.Log(sum)
	t.Log(commit)

	commit, err = proofIns.GetSelectFileCommit(big.NewInt(0))
	if err != nil {
		t.Log(err)
	}
	t.Log(commit)

	// commit, err = proofIns.GetSelectFileCommit(big.NewInt(1))
	// if err != nil {
	// 	t.Log(err)
	// }
	// t.Log(commit)

	commit, err = proofIns.GetSelectFileCommit(big.NewInt(2))
	if err != nil {
		t.Log(err)
	}
	t.Log(commit)
}

func TestChallenge(t *testing.T) {
	sk, err := crypto.HexToECDSA(globalPrivateKeys[2])
	if err != nil {
		t.Fatal(err)
	}

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

	proofIns, err := NewProofInstance(sk, "dev")
	if err != nil {
		t.Fatal(err)
	}

	setting, err := proofIns.GetSettingInfo()
	if err != nil {
		t.Fatal(err)
	}

	_, _, last, err := proofIns.GetVerifyInfo()
	if err != nil {
		t.Fatal(err)
	}

	amount, err := tokenIns.BalanceOf(&bind.CallOpts{}, crypto.PubkeyToAddress(sk.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(amount)

	if time.Now().Unix() > last.Int64() {
		start := time.Now().Unix()
		chalTime := int64(setting.Interval) + int64(setting.Period)
		dur := (start - last.Int64()) % chalTime
		wait := chalTime - dur
		time.Sleep(time.Duration(wait+1) * time.Second)
		last = big.NewInt(time.Now().Unix())
	} else {
		wait := last.Int64() - time.Now().Unix()
		time.Sleep(time.Duration(wait+1) * time.Second)
	}

	info, err := proofIns.GetChallengeInfo()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(info, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))

	err = proofIns.Challenge(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("challenge-0")

	info, err = proofIns.GetChallengeInfo()
	if err != nil {
		t.Fatal(err)
	}
	data, err = json.MarshalIndent(info, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))

	amount, err = tokenIns.BalanceOf(&bind.CallOpts{}, crypto.PubkeyToAddress(sk.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(amount)
	for {
		info, err := proofIns.GetChallengeInfo()
		if err != nil {
			t.Fatal(err)
		}

		if info.ChalStatus%2 == 1 {
			if time.Now().Unix() > last.Int64()+int64(setting.RespondTime)*int64(info.ChalStatus+1) {
				err = proofIns.EndChallenge()
				if err != nil {
					t.Fatal(err)
				}
				t.Log("we success beacause they failed to generate aggregate commit")
				return
			}
		} else {
			// one last step proof submitted, check if we win
			if info.ChalStatus == 0 {
				amount2, err := tokenIns.BalanceOf(&bind.CallOpts{}, crypto.PubkeyToAddress(sk.PublicKey))
				if err != nil {
					t.Fatal(err)
				}
				t.Log(amount2)

				if amount2.Cmp(amount) == 1 {
					t.Log("we success beacause they failed on the last prove")
				} else {
					t.Log("we failed beacause they success on the last prove")
				}

				return
			} else {
				t.Log(time.Now().Unix(), last.Int64()+int64(setting.RespondTime)*int64(info.ChalStatus+1))
				index := uint8(rand.Int()) % 10
				// index := uint8(0)
				err = proofIns.Challenge(index)
				if err != nil {
					t.Fatal(err)
				}

				t.Log("challenge-", info.ChalStatus)
			}
		}

		time.Sleep(time.Second)
	}
}

// func TestChallenge(t *testing)

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

func TestGetAddress(t *testing.T) {
	instanceAddr, endpoint := com.GetInsEndPointByChain("dev")

	client, err := ethclient.DialContext(context.TODO(), endpoint)
	if err != nil {
		t.Fatal(err)
	}

	// chainID, err := client.NetworkID(context.Background())
	// if err != nil {
	// 	return err
	// }

	instanceIns, err := inst.NewInstance(instanceAddr, client)
	if err != nil {
		t.Fatal(err)
	}

	address, err := instanceIns.Instances(&bind.CallOpts{}, com.TypeFileProof)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(address)

	address, err = instanceIns.Instances(&bind.CallOpts{}, com.TypeFileProofControl)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(address)

	address, err = instanceIns.Instances(&bind.CallOpts{}, com.TypeFileProofProxy)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(address)
}

func TestBalance(t *testing.T) {
	balance, balanceErc20, err := getBalance("dev", globalPrivateKeys[0])
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Log(balance)
	t.Log(balanceErc20)

	balance, balanceErc20, err = getBalance("dev", globalPrivateKeys[1])
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Log(balance)
	t.Log(balanceErc20)

	balance, balanceErc20, err = getBalance("dev", globalPrivateKeys[2])
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Log(balance)
	t.Log(balanceErc20)
}

func TestTransfer(t *testing.T) {
	sk, err := crypto.HexToECDSA(globalPrivateKeys[1])
	if err != nil {
		t.Fatal(err.Error())
	}

	var pledge = big.NewInt(1000000000000000000)
	var amount = new(big.Int).Mul(pledge, big.NewInt(1000))
	t.Log(amount)

	transferMemo("dev", globalPrivateKeys[0], crypto.PubkeyToAddress(sk.PublicKey), amount)
	transferEth("dev", globalPrivateKeys[0], crypto.PubkeyToAddress(sk.PublicKey), pledge)
}

func getBalance(chain string, sk string) (*big.Int, *big.Int, error) {
	instanceAddr, endpoint := com.GetInsEndPointByChain(chain)

	client, err := ethclient.DialContext(context.TODO(), endpoint)
	if err != nil {
		return nil, nil, err
	}

	// chainID, err := client.NetworkID(context.Background())
	// if err != nil {
	// 	return err
	// }

	instanceIns, err := inst.NewInstance(instanceAddr, client)
	if err != nil {
		return nil, nil, err
	}

	tokenAddr, err := instanceIns.Instances(&bind.CallOpts{}, com.TypeERC20)
	if err != nil {
		return nil, nil, err
	}

	tokenIns, err := erc.NewERC20(tokenAddr, client)
	if err != nil {
		return nil, nil, err
	}

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

func transferMemo(chain string, fromSK string, to common.Address, amount *big.Int) error {
	instanceAddr, endpoint := com.GetInsEndPointByChain(chain)

	client, err := ethclient.DialContext(context.TODO(), endpoint)
	if err != nil {
		return err
	}

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return err
	}

	instanceIns, err := inst.NewInstance(instanceAddr, client)
	if err != nil {
		return err
	}

	tokenAddr, err := instanceIns.Instances(&bind.CallOpts{}, com.TypeERC20)
	if err != nil {
		return err
	}

	tokenIns, err := erc.NewERC20(tokenAddr, client)
	if err != nil {
		return err
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

func transferEth(chain string, fromSK string, to common.Address, amount *big.Int) error {
	_, endpoint := com.GetInsEndPointByChain(chain)

	client, err := ethclient.DialContext(context.TODO(), endpoint)
	if err != nil {
		return err
	}

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
