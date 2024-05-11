package proof

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/xerrors"

	com "github.com/memoio/contractsv2/common"
	"github.com/memoio/contractsv2/go_contracts/auth"
	"github.com/memoio/contractsv2/go_contracts/erc"
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
	proofProxyAddr      common.Address
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
	defer client.Close()

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
	proofAddr, err := instanceIns.Instances(&bind.CallOpts{}, com.TypeFileProof)
	if err != nil {
		return nil, err
	}

	// get proof proxy address
	proofProxyAddr, err := instanceIns.Instances(&bind.CallOpts{}, com.TypeFileProofProxy)
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
		proofProxyAddr:      proofProxyAddr,
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

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return err
	}

	erc20Ins, err := erc.NewERC20(ins.tokenAddr, client)
	if err != nil {
		return err
	}

	setting, err := ins.GetSettingInfo()
	if err != nil {
		return err
	}

	// // check credential
	hash := ins.GetCredentialHash(ins.transactor.From, commit, size, start, end)
	publicKey, err := crypto.SigToPub(hash, credential)
	if err != nil {
		return err
	}
	if crypto.PubkeyToAddress(*publicKey).Hex() != setting.Submitter.Hex() {
		return xerrors.Errorf("credential is not right")
	}

	amount := big.NewInt(int64(setting.Price))
	amount.Mul(big.NewInt(int64(size)), amount)
	amount.Mul(amount, new(big.Int).Sub(end, start))
	tx, err := erc20Ins.Approve(ins.transactor, ins.proofAddr, amount)
	if err != nil {
		return err
	}
	err = CheckTx(ins.endpoint, ins.transactor.From, tx, "Approve")
	if err != nil {
		return err
	}

	tx, err = proofIns.AddFile(ins.transactor, ToSolidityG1(commit), size, start, end, credential)
	if err != nil {
		return err
	}

	return CheckTx(ins.endpoint, ins.transactor.From, tx, "AddFile")
}

func (ins *ProofInstance) GenerateRnd() error {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return err
	}

	tx, err := proofIns.GenRnd(ins.transactor)
	if err != nil {
		return err
	}

	return CheckTx(ins.endpoint, ins.transactor.From, tx, "GenerateRnd")
}

func (ins *ProofInstance) SubmitAggregationProof(randomPoint fr.Element, commit bls12381.G1Affine, proof kzg.OpeningProof) error {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return err
	}

	info, err := proofIns.GetVerifyInfo(&bind.CallOpts{})
	if err != nil {
		return err
	}

	var rnd fr.Element
	rnd.SetBytes(info.Rnd[:])
	if !rnd.Equal(&randomPoint) {
		return xerrors.Errorf("rnd is not equal to on-chain rnd")
	}

	tx, err := proofIns.SubmitProof(ins.transactor, info.Rnd, ToSolidityG1(commit), ToSolidityProof(proof))
	if err != nil {
		return err
	}

	return CheckTx(ins.endpoint, ins.transactor.From, tx, "SubmitAggregationProof")
}

func (ins *ProofInstance) Challenge(challengeIndex uint8) error {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return err
	}

	erc20Ins, err := erc.NewERC20(ins.tokenAddr, client)
	if err != nil {
		return err
	}

	setting, err := ins.GetSettingInfo()
	if err != nil {
		return err
	}

	challenge, err := ins.GetChallengeInfo()
	if err != nil {
		return err
	}

	if challenge.ChalStatus == 0 {
		tx, err := erc20Ins.Approve(ins.transactor, ins.proofAddr, setting.ChalPledge)
		if err != nil {
			return err
		}
		err = CheckTx(ins.endpoint, ins.transactor.From, tx, "Approve")
		if err != nil {
			return err
		}
	}

	tx, err := proofIns.DoChallenge(ins.transactor, challengeIndex)
	if err != nil {
		return err
	}

	return CheckTx(ins.endpoint, ins.transactor.From, tx, "Challenge")
}

func (ins *ProofInstance) ResponseChallenge(commits [10]bls12381.G1Affine) error {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
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

	return CheckTx(ins.endpoint, ins.transactor.From, tx, "ResponseChallenge")
}

func (ins *ProofInstance) OneStepProve(commits []bls12381.G1Affine) error {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
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

	return CheckTx(ins.endpoint, ins.transactor.From, tx, "OneStepProve")
}

func (ins *ProofInstance) EndChallenge() error {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return err
	}

	tx, err := proofIns.EndChallenge(ins.transactor)
	if err != nil {
		return err
	}

	return CheckTx(ins.endpoint, ins.transactor.From, tx, "EndChallenge")
}

func (ins *ProofInstance) WithdrawMissedProfit() error {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return err
	}

	tx, err := proofIns.WithdrawMissedProfit(ins.transactor)
	if err != nil {
		return err
	}

	return CheckTx(ins.endpoint, ins.transactor.From, tx, "WithdrawMissedProfit")
}

func (ins *ProofInstance) AlterSetting(setting SettingInfo, vk bls12381.G2Affine, signs [5][]byte) error {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return err
	}

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

	return CheckTx(ins.endpoint, ins.transactor.From, tx, "AlterSetting")
}

func (ins *ProofInstance) GetSelectFileCommit(index *big.Int) (bls12381.G1Affine, error) {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return bls12381.G1Affine{}, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return bls12381.G1Affine{}, err
	}

	commit, err := proofIns.SelectFiles(&bind.CallOpts{}, index)
	if err != nil {
		return bls12381.G1Affine{}, err
	}

	return FromSolidityG1(commit), nil
}

func (ins *ProofInstance) GetFileCommit(index *big.Int) (*big.Int, bls12381.G1Affine, error) {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return nil, bls12381.G1Affine{}, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return nil, bls12381.G1Affine{}, err
	}

	info, err := proofIns.GetCommit(&bind.CallOpts{}, index)
	if err != nil {
		return nil, bls12381.G1Affine{}, err
	}

	return info.Sum, FromSolidityG1(info.Commitment), nil
}

// func (ins *ProofInstance) GetProofInfo() error {
// 	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
// 	if err != nil {
// 		return err
// 	}
// 	defer client.Close()

// 	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
// 	if err != nil {
// 		return err
// 	}

// 	_, err = proofIns.GetProofInfo(&bind.CallOpts{})
// 	if err != nil {
// 		return err
// 	}

// 	return nil

// 	// info, err := proofIns.GetCommit(&bind.CallOpts{}, index)
// 	// if err != nil {
// 	// 	return err
// 	// }
// }

func (ins *ProofInstance) GetVerifyInfo() (fr.Element, bool, *big.Int, error) {
	rnd := fr.Element{}
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return rnd, false, nil, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return rnd, false, nil, err
	}

	res, err := proofIns.GetVerifyInfo(&bind.CallOpts{})

	return *rnd.SetBytes(res.Rnd[:]), res.Lock, res.Last, err
}

func (ins *ProofInstance) GetRndRawBytes() ([32]byte, error) {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return [32]byte{}, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return [32]byte{}, err
	}

	res, err := proofIns.GetVerifyInfo(&bind.CallOpts{})
	return res.Rnd, err
}

func (ins *ProofInstance) GetProfitInfo() (ProfitInfo, error) {
	var info ProfitInfo
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return info, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
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

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
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

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return info, err
	}

	return proofIns.GetSettingInfo(&bind.CallOpts{})
}

func (ins *ProofInstance) GetVK() (bls12381.G2Affine, error) {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return bls12381.G2Affine{}, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return bls12381.G2Affine{}, err
	}

	vkSol, err := proofIns.GetVK(&bind.CallOpts{})
	return FromSolidityG2(vkSol), err
}

func (ins *ProofInstance) FilterAddFile(opt *bind.FilterOpts, accounts []common.Address) ([]AddFileEvent, error) {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewIFileProof(ins.proofAddr, client)
	if err != nil {
		return nil, err
	}

	addFileIter, err := proofIns.FilterAddFile(opt, accounts)
	if err != nil {
		return nil, err
	}
	defer addFileIter.Close()

	var addFiles []AddFileEvent
	for addFileIter.Next() {
		addFile := AddFileEvent{
			Account: addFileIter.Event.Account,
			Commit:  FromSolidityG1(addFileIter.Event.Etag),
			Start:   addFileIter.Event.Start,
			End:     addFileIter.Event.End,
			Size:    addFileIter.Event.Size,
			Price:   addFileIter.Event.Price,
			Raw:     addFileIter.Event.Raw,
		}

		addFiles = append(addFiles, addFile)
	}

	return addFiles, nil
}

func (ins *ProofInstance) FilterSubmitProof(opt *bind.FilterOpts, rnds [][32]byte) ([]SubmitProofEvent, error) {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewIFileProof(ins.proofAddr, client)
	if err != nil {
		return nil, err
	}

	proofIter, err := proofIns.FilterSubmitProof(opt, rnds)
	if err != nil {
		return nil, err
	}
	defer proofIter.Close()

	var proofs []SubmitProofEvent
	var rnd fr.Element
	for proofIter.Next() {
		rnd.SetBytes(proofIter.Event.Rnd[:])
		proof := SubmitProofEvent{
			Rnd: rnd,
			Cn:  FromSolidityG1(proofIter.Event.Cn),
			Pn:  FromSolidityProof(proofIter.Event.Pn),
			Res: proofIter.Event.Res,
			Raw: proofIter.Event.Raw,
		}
		proofs = append(proofs, proof)
	}

	return proofs, nil
}

func (ins *ProofInstance) FilterFraud(opt *bind.FilterOpts, rnds [][32]byte, submitters []common.Address, challengers []common.Address) ([]FraudEvent, error) {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewIFileProof(ins.proofAddr, client)
	if err != nil {
		return nil, err
	}

	fraudIter, err := proofIns.FilterFraud(opt, rnds, submitters, challengers)
	if err != nil {
		return nil, err
	}
	defer fraudIter.Close()

	var frauds []FraudEvent
	var rndEle = fr.Element{}
	for fraudIter.Next() {
		fraud := FraudEvent{
			Rnd:        *rndEle.SetBytes(fraudIter.Event.Rnd[:]),
			Challenger: fraudIter.Event.Challenger,
			Submmitter: fraudIter.Event.Submitter,
			Fine:       fraudIter.Event.Fine,
			Reward:     fraudIter.Event.Reward,
		}

		frauds = append(frauds, fraud)
	}

	return frauds, nil
}

func (ins *ProofInstance) FilterNoFraud(opt *bind.FilterOpts, rnds [][32]byte, submitters []common.Address, challengers []common.Address) ([]NoFraudEvent, error) {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewIFileProof(ins.proofAddr, client)
	if err != nil {
		return nil, err
	}

	fraudIter, err := proofIns.FilterNoFraud(opt, rnds, submitters, challengers)
	if err != nil {
		return nil, err
	}
	defer fraudIter.Close()

	var nofrauds []NoFraudEvent
	var rndEle = fr.Element{}
	for fraudIter.Next() {
		nofraud := NoFraudEvent{
			Rnd:          *rndEle.SetBytes(fraudIter.Event.Rnd[:]),
			Challenger:   fraudIter.Event.Challenger,
			Submmitter:   fraudIter.Event.Submitter,
			Compensation: fraudIter.Event.Compensation,
		}

		nofrauds = append(nofrauds, nofraud)
	}

	return nofrauds, nil
}

func (ins *ProofInstance) IsSubmitterWinner() (bool, error) {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return false, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return false, err
	}

	info, err := proofIns.GetVerifyInfo(&bind.CallOpts{})
	if err != nil {
		return false, err
	}

	frauds, err := ins.FilterFraud(&bind.FilterOpts{}, [][32]byte{info.Rnd}, nil, nil)
	if err != nil {
		return false, err
	}
	if len(frauds) > 0 {
		return false, nil
	}

	nofrauds, err := ins.FilterFraud(&bind.FilterOpts{}, [][32]byte{info.Rnd}, nil, nil)
	if err != nil {
		return false, err
	}
	if len(nofrauds) == 0 {
		challengeInfo, err := ins.GetChallengeInfo()
		if err != nil {
			return false, err
		}

		if challengeInfo.ChalStatus != 0 {
			return false, xerrors.Errorf("The challenge is not completed")
		} else {
			return false, xerrors.Errorf("Nobody has challenged yet")
		}
	}

	return true, nil
}

func (ins *ProofInstance) GetAlterSettingInfoHash(setting SettingInfo, vk bls12381.G2Affine) ([]byte, error) {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	authIns, err := auth.NewAuth(ins.authAddr, client)
	if err != nil {
		return nil, err
	}

	nonce, err := authIns.Nonce(&bind.CallOpts{})
	if err != nil {
		return nil, err
	}

	return getAlterSettingInfoHash(ins.proofControllerAddr, ins.authAddr, setting, vk, nonce), nil
}

func (ins *ProofInstance) GetCredentialHash(address common.Address, commit bls12381.G1Affine, size uint64, start *big.Int, end *big.Int) []byte {
	return getCredentialHash(ins.proofAddr, address, commit, size, start, end)
}

// func GetCredentialHash(chain string, address common.Address, commit bls12381.G1Affine, size uint64, start *big.Int, end *big.Int) ([]byte, error) {
// 	instanceAddr, endpoint := com.GetInsEndPointByChain(chain)

// 	client, err := ethclient.DialContext(context.TODO(), endpoint)
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer client.Close()

// 	instanceIns, err := inst.NewInstance(instanceAddr, client)
// 	if err != nil {
// 		return nil, err
// 	}

// 	proofAddr, err := instanceIns.Instances(&bind.CallOpts{}, com.TypeFileProof)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return getCredentialHash(proofAddr, address, commit, size, start, end), nil
// }

// CheckTx check whether transaction is successful through receipt
func CheckTx(endPoint string, from common.Address, tx *types.Transaction, name string) error {
	var receipt *types.Receipt

	t := checkTxSleepTime
	for i := 0; i < 10; i++ {
		time.Sleep(time.Duration(t) * time.Second)
		receipt = com.GetTransactionReceipt(endPoint, tx.Hash())
		if receipt != nil {
			break
		}
		t = nextBlockTime
	}

	if receipt == nil {
		return xerrors.Errorf("%s: cann't get transaction(%s) receipt, not packaged", name, tx.Hash())
	}

	// 0 means fail
	if receipt.Status == 0 {
		if receipt.GasUsed != receipt.CumulativeGasUsed {
			return xerrors.Errorf("%s: transaction(%s) exceed gas limit", name, tx.Hash())
		}
		reason, err := getErrorReason(context.TODO(), endPoint, from, tx)
		if err != nil {
			return xerrors.Errorf("%s: transaction(%s) mined but execution failed: %s", name, tx.Hash(), err.Error())
		}
		return xerrors.Errorf("%s: transaction(%s) revert(%s)", name, tx.Hash(), reason)
	}
	return nil
}
