package proof

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/xerrors"

	com "github.com/memoio/contractsv2/common"
	"github.com/memoio/contractsv2/go_contracts/auth"
	inst "github.com/memoio/contractsv2/go_contracts/instance"
	proxyfileproof "github.com/memoio/did-solidity/go-contracts/proxy-proof"
)

var (
	checkTxSleepTime = 6 // 先等待6s（出块时间加1）
	nextBlockTime    = 5 // 出块时间5s
)

type ProofInstance struct {
	endpoint            string
	transactor          *bind.TransactOpts
	proofAddr           common.Address
	proofControllerAddr common.Address
	tokenAddr           common.Address
	authAddr            common.Address
}

func NewProofInstance(privateKey *ecdsa.PrivateKey, chain string) (*ProofInstance, error) {
	instanceAddr, endpoint := com.GetInsEndPointByChain(chain)

	client, err := ethclient.DialContext(context.TODO(), endpoint)
	if err != nil {
		return nil, err
	}

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		chainID = big.NewInt(985)
	}

	// new instance
	instanceIns, err := inst.NewInstance(instanceAddr, client)
	if err != nil {
		return nil, err
	}

	// get proof address
	proofAddr, err := instanceIns.Instances(&bind.CallOpts{}, com.TypeFileProofProxy)
	if err != nil {
		return nil, err
	}

	// get token address
	tokenAddr, err := instanceIns.Instances(&bind.CallOpts{}, com.TypeERC20)
	if err != nil {
		return nil, err
	}

	// get proof controller address
	proofControllerAddr, err := instanceIns.Instances(&bind.CallOpts{}, com.TypeFileProofControl)
	if err != nil {
		return nil, err
	}

	// get auth address
	authAddr, err := instanceIns.Instances(&bind.CallOpts{}, com.TypeAuth)
	if err != nil {
		return nil, err
	}

	// new auth
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
	if err != nil {
		return nil, err
	}
	auth.Value = big.NewInt(0)      // in wei
	auth.GasLimit = uint64(3000000) // in units
	// auth.GasPrice = big.NewInt(1000)

	return &ProofInstance{
		endpoint:            endpoint,
		transactor:          auth,
		proofAddr:           proofAddr,
		proofControllerAddr: proofControllerAddr,
		tokenAddr:           tokenAddr,
		authAddr:            authAddr,
	}, nil
}

func (ins *ProofInstance) AddFile(commit bls12381.G1Affine, size uint64, start *big.Int, end *big.Int, credential []byte) error {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofAddr, client)
	if err != nil {
		return err
	}

	tx, err := proofIns.AddFile(ins.transactor, ToSolidityG1(commit), size, start, end, credential)
	if err != nil {
		return err
	}

	return CheckTx(ins.endpoint, tx.Hash(), "AddFile")
}

func (ins *ProofInstance) GenerateRnd() error {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofAddr, client)
	if err != nil {
		return err
	}

	tx, err := proofIns.GenRnd(ins.transactor)
	if err != nil {
		return err
	}

	return CheckTx(ins.endpoint, tx.Hash(), "GenerateRnd")
}

func (ins *ProofInstance) SubmitAggregationProof(randomPoint fr.Element, commit bls12381.G1Affine, proof kzg.OpeningProof) error {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofAddr, client)
	if err != nil {
		return err
	}

	tx, err := proofIns.SubmitProof(ins.transactor, randomPoint.Bytes(), ToSolidityG1(commit), ToSolidityProof(proof))
	if err != nil {
		return err
	}

	return CheckTx(ins.endpoint, tx.Hash(), "SubmitAggregationProof")
}

func (ins *ProofInstance) Challenge(challengeIndex uint8) error {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofAddr, client)
	if err != nil {
		return err
	}

	tx, err := proofIns.DoChallenge(ins.transactor, challengeIndex)
	if err != nil {
		return err
	}

	return CheckTx(ins.endpoint, tx.Hash(), "Challenge")
}

func (ins *ProofInstance) ResponseChallenge(commits [10]bls12381.G1Affine) error {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofAddr, client)
	if err != nil {
		return err
	}

	var commitsBytes [10][4][32]byte
	for index, commit := range commits {
		commitsBytes[index] = ToSolidityG1(commit)
	}
	tx, err := proofIns.ResponseChal(ins.transactor, commitsBytes)
	if err != nil {
		return err
	}

	return CheckTx(ins.endpoint, tx.Hash(), "ResponseChallenge")
}

func (ins *ProofInstance) OneStepProve(commits []bls12381.G1Affine) error {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofAddr, client)
	if err != nil {
		return err
	}

	var commitsBytes [][4][32]byte = make([][4][32]byte, len(commits))
	for index, commit := range commits {
		commitsBytes[index] = ToSolidityG1(commit)
	}
	tx, err := proofIns.OneStepProve(ins.transactor, commitsBytes)
	if err != nil {
		return err
	}

	return CheckTx(ins.endpoint, tx.Hash(), "OneStepProve")
}

func (ins *ProofInstance) EndChallenge() error {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofAddr, client)
	if err != nil {
		return err
	}

	tx, err := proofIns.EndChallenge(ins.transactor)
	if err != nil {
		return err
	}

	return CheckTx(ins.endpoint, tx.Hash(), "EndChallenge")
}

func (ins *ProofInstance) WithdrawMissedProfit() error {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofAddr, client)
	if err != nil {
		return err
	}

	tx, err := proofIns.WithdrawMissedProfit(ins.transactor)
	if err != nil {
		return err
	}

	return CheckTx(ins.endpoint, tx.Hash(), "WithdrawMissedProfit")
}

func (ins *ProofInstance) AlterSetting(setting SettingInfo, vk bls12381.G2Affine, sks [5]string) error {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofAddr, client)
	if err != nil {
		return err
	}

	authIns, err := auth.NewAuth(ins.authAddr, client)
	if err != nil {
		return err
	}

	nonce, err := authIns.Nonce(&bind.CallOpts{})
	if err != nil {
		return err
	}
	fmt.Println(nonce)

	hash := GetAlterSettingInfoHash(ins.proofControllerAddr, ins.authAddr, setting, vk, nonce)
	signs := com.GetSigns(hash, sks)

	info := proxyfileproof.IFileProofSettingInfo{
		Interval:        setting.Interval,
		Period:          setting.Period,
		ChalSum:         setting.ChalSum,
		RespondTime:     setting.RespondTime,
		Price:           setting.Price,
		Submitter:       setting.Submitter,
		Receiver:        setting.Receiver,
		Foundation:      setting.Foundation,
		ChalRewardRatio: setting.ChalRewardRatio,
		ChalPledge:      setting.ChalPledge,
		Vk:              ToSolidityG2(vk),
	}

	tx, err := proofIns.AlterSetting(ins.transactor, info, signs)
	if err != nil {
		return err
	}

	return CheckTx(ins.endpoint, tx.Hash(), "AlterSetting")
}

// func (ins *ProofInstance) GetFirstTime() (uint64, error) {
// 	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
// 	if err != nil {
// 		return 0, err
// 	}
// 	defer client.Close()

// 	contractAbi, err := abi.JSON(strings.NewReader(proxyfileproof.ProxyProofABI))
// 	if err != nil {
// 		return 0, err
// 	}

// 	events, err := client.FilterLogs(context.TODO(), ethereum.FilterQuery{
// 		FromBlock: nil,
// 		Addresses: []common.Address{com.InstanceAddr},
// 		Topics:    [][]common.Hash{{contractAbi.Events["AddFile"].ID}},
// 	})
// 	if err != nil {
// 		return 0, err
// 	}
// 	if len(events) == 0 {
// 		return 0, nil
// 	}

// 	header, err := client.HeaderByNumber(context.Background(), big.NewInt(int64(events[0].BlockNumber)))
// 	if err != nil {
// 		return 0, err
// 	}

// 	return header.Time, nil
// }

func (ins *ProofInstance) GetVerifyInfo() (fr.Element, *big.Int, error) {
	rnd := fr.Element{}
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return rnd, nil, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofAddr, client)
	if err != nil {
		return rnd, nil, err
	}

	res, err := proofIns.GetVerifyInfo(&bind.CallOpts{})

	return *rnd.SetBytes(res.Rnd[:]), res.Last, err
}

func (ins *ProofInstance) GetProfitInfo() (ProfitInfo, error) {
	var info ProfitInfo
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return info, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofAddr, client)
	if err != nil {
		return info, err
	}

	return proofIns.GetProfitInfo(&bind.CallOpts{})
}

func (ins *ProofInstance) GetChallengeInfo() (ChallengeInfo, error) {
	var info ChallengeInfo
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return info, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofAddr, client)
	if err != nil {
		return info, err
	}

	return proofIns.GetChallengeInfo(&bind.CallOpts{})
}

func (ins *ProofInstance) GetSettingInfo() (SettingInfo, error) {
	var info SettingInfo

	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return info, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofAddr, client)
	if err != nil {
		return info, err
	}

	return proofIns.GetSettingInfo(&bind.CallOpts{})
}

// CheckTx check whether transaction is successful through receipt
func CheckTx(endPoint string, txHash common.Hash, name string) error {
	var receipt *types.Receipt

	t := checkTxSleepTime
	for i := 0; i < 10; i++ {
		time.Sleep(time.Duration(t) * time.Second)
		receipt = com.GetTransactionReceipt(endPoint, txHash)
		if receipt != nil {
			break
		}
		t = nextBlockTime
	}

	if receipt == nil {
		return xerrors.Errorf("%s: cann't get transaction(%s) receipt, not packaged", name, txHash)
	}

	// 0 means fail
	if receipt.Status == 0 {
		if receipt.GasUsed != receipt.CumulativeGasUsed {
			return xerrors.Errorf("%s: transaction(%s) exceed gas limit", name, txHash)
		}
		return xerrors.Errorf("%s: transaction(%s) mined but execution failed, please check your tx input", name, txHash)
	}
	return nil
}
