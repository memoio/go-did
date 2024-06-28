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
	pledgeAddr          common.Address
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

	// get pledge address
	pledgeAddr, err := instanceIns.Instances(&bind.CallOpts{}, com.TypeFileProofPledge)
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
		pledgeAddr:          pledgeAddr,
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

	submitterInfo, err := ins.GetSubmittersInfo()
	if err != nil {
		return err
	}

	// // check credential
	hash := ins.GetCredentialHash(ins.transactor.From, commit, size, start, end)
	publicKey, err := crypto.SigToPub(hash, credential)
	if err != nil {
		return err
	}
	if crypto.PubkeyToAddress(*publicKey).Hex() != submitterInfo.MainSubmitter.Hex() {
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

func (ins *ProofInstance) BeSubmitter() error {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return err
	}

	tx, err := proofIns.BeSubmitter(ins.transactor)
	if err != nil {
		return err
	}

	return CheckTx(ins.endpoint, ins.transactor.From, tx, "BeSubmitter")
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

	setting, err := ins.GetSettingInfo()
	if err != nil {
		return err
	}

	pledgeBal, err := proofIns.Bal(&bind.CallOpts{}, ins.transactor.From)
	if err != nil {
		return err
	}

	if pledgeBal.Cmp(setting.SubPledge) < 0 {
		erc20Ins, err := erc.NewERC20(ins.tokenAddr, client)
		if err != nil {
			return err
		}
		amount := pledgeBal.Sub(setting.SubPledge, pledgeBal)
		tx, err := erc20Ins.Approve(ins.transactor, ins.pledgeAddr, amount)
		if err != nil {
			return err
		}
		err = CheckTx(ins.endpoint, ins.transactor.From, tx, "Approve")
		if err != nil {
			return err
		}
	}

	rndBytes, err := proofIns.Rnd(&bind.CallOpts{})
	if err != nil {
		return err
	}

	var rnd fr.Element
	rnd.SetBytes(rndBytes[:])
	if !rnd.Equal(&randomPoint) {
		return xerrors.Errorf("rnd is not equal to on-chain rnd")
	}

	tx, err := proofIns.SubmitProof(ins.transactor, ToSolidityG1(commit), ToSolidityProof(proof))
	if err != nil {
		return err
	}

	return CheckTx(ins.endpoint, ins.transactor.From, tx, "SubmitAggregationProof")
}

func (ins *ProofInstance) ChallengePn(submitter common.Address) error {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return err
	}

	setting, err := ins.GetSettingInfo()
	if err != nil {
		return err
	}

	pledgeBal, err := proofIns.Bal(&bind.CallOpts{}, ins.transactor.From)
	if err != nil {
		return err
	}

	if pledgeBal.Cmp(setting.ChalPledge) < 0 {
		erc20Ins, err := erc.NewERC20(ins.tokenAddr, client)
		if err != nil {
			return err
		}
		amount := pledgeBal.Sub(setting.ChalPledge, pledgeBal)
		tx, err := erc20Ins.Approve(ins.transactor, ins.pledgeAddr, amount)
		if err != nil {
			return err
		}
		err = CheckTx(ins.endpoint, ins.transactor.From, tx, "Approve")
		if err != nil {
			return err
		}
	}

	tx, err := proofIns.ChallengePn(ins.transactor, submitter)
	if err != nil {
		return err
	}

	return CheckTx(ins.endpoint, ins.transactor.From, tx, "ChallengePn")
}

func (ins *ProofInstance) ChallengeCn(submitter common.Address, challengeIndex uint8) error {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return err
	}

	setting, err := ins.GetSettingInfo()
	if err != nil {
		return err
	}

	pledgeBal, err := proofIns.Bal(&bind.CallOpts{}, ins.transactor.From)
	if err != nil {
		return err
	}

	if pledgeBal.Cmp(setting.ChalPledge) < 0 {
		erc20Ins, err := erc.NewERC20(ins.tokenAddr, client)
		if err != nil {
			return err
		}
		amount := pledgeBal.Sub(setting.ChalPledge, pledgeBal)
		tx, err := erc20Ins.Approve(ins.transactor, ins.pledgeAddr, amount)
		if err != nil {
			return err
		}
		err = CheckTx(ins.endpoint, ins.transactor.From, tx, "Approve")
		if err != nil {
			return err
		}
	}

	tx, err := proofIns.ChallengeCn(ins.transactor, submitter, challengeIndex)
	if err != nil {
		return err
	}

	return CheckTx(ins.endpoint, ins.transactor.From, tx, "ChallengeCn")
}

func (ins *ProofInstance) ResponseChallenge(commits [10]bls12381.G1Affine, lastOneStep bool) error {
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
	tx, err := proofIns.ResponseChal(ins.transactor, commitsBytes, lastOneStep)
	if err != nil {
		return err
	}

	return CheckTx(ins.endpoint, ins.transactor.From, tx, "ResponseChallenge")
}

func (ins *ProofInstance) EndChallenge(submitter common.Address) error {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return err
	}

	tx, err := proofIns.EndChallenge(ins.transactor, submitter)
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

func (ins *ProofInstance) Pledge(amount *big.Int) error {
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

	tx, err := erc20Ins.Approve(ins.transactor, ins.pledgeAddr, amount)
	if err != nil {
		return err
	}
	err = CheckTx(ins.endpoint, ins.transactor.From, tx, "Approve")
	if err != nil {
		return err
	}

	tx, err = proofIns.FpPledge(ins.transactor, amount)
	if err != nil {
		return err
	}

	return CheckTx(ins.endpoint, ins.transactor.From, tx, "Pledge")
}

func (ins *ProofInstance) Withdraw() error {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return err
	}

	tx, err := proofIns.FpWithdraw(ins.transactor)
	if err != nil {
		return err
	}

	return CheckTx(ins.endpoint, ins.transactor.From, tx, "Withdraw")
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
		Interval:          setting.Interval,
		Period:            setting.Period,
		ChalSum:           setting.ChalSum,
		RespondTime:       setting.RespondTime,
		Price:             setting.Price,
		PenaltyPercentage: setting.PenaltyPercentage,
		SubPledge:         setting.SubPledge,
		ChalPledge:        setting.ChalPledge,
		Vk:                ToSolidityG2(vk),
	}

	tx, err := proofIns.AlterSetting(ins.transactor, info, signs)
	if err != nil {
		return err
	}

	return CheckTx(ins.endpoint, ins.transactor.From, tx, "AlterSetting")
}

func (ins *ProofInstance) AlterFoundation(foundation common.Address, signs [5][]byte) error {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return err
	}

	tx, err := proofIns.AlterFoundation(ins.transactor, foundation, signs)
	if err != nil {
		return err
	}

	return CheckTx(ins.endpoint, ins.transactor.From, tx, "AlterFoundation")
}

func (ins *ProofInstance) GetSelectFileCommit(submitter common.Address, index *big.Int) (bls12381.G1Affine, error) {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return bls12381.G1Affine{}, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return bls12381.G1Affine{}, err
	}

	commit, err := proofIns.SelectFiles(&bind.CallOpts{}, submitter, index)
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

	rnd, err := proofIns.Rnd(&bind.CallOpts{})
	return rnd, err
}

func (ins *ProofInstance) GetLast() (*big.Int, error) {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return nil, err
	}

	last, err := proofIns.Last(&bind.CallOpts{})
	return last, err
}

func (ins *ProofInstance) GetFilesAmount() (*big.Int, error) {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return nil, err
	}

	amount, err := proofIns.FilesNum(&bind.CallOpts{})
	return amount, err
}

func (ins *ProofInstance) GetFinalExpire() (*big.Int, error) {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return nil, err
	}

	amount, err := proofIns.FinalExpire(&bind.CallOpts{})
	return amount, err
}

func (ins *ProofInstance) GetChallengeInfo(submitter common.Address) (ChallengeInfo, error) {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return ChallengeInfo{}, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return ChallengeInfo{}, err
	}

	dividedCn, err := proofIns.DividedCn(&bind.CallOpts{}, submitter)
	if err != nil {
		return ChallengeInfo{}, err
	}

	info, err := proofIns.Challenges(&bind.CallOpts{}, submitter)
	if err != nil {
		return ChallengeInfo{}, err
	}
	return ChallengeInfo{Status: info.Status, ChalIndex: info.ChalIndex, Challenger: info.Challenger, StartIndex: info.StartIndex, DividedCn: dividedCn}, nil
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

func (ins *ProofInstance) GetSubmittersInfo() (SubmitterInfo, error) {
	var info SubmitterInfo
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return info, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return info, err
	}

	return proofIns.SubmittersInfo(&bind.CallOpts{})
}

func (ins *ProofInstance) IsSubmitter(account common.Address) (bool, error) {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return false, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return false, err
	}

	return proofIns.IsSubmitter(&bind.CallOpts{}, account)
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

func (ins *ProofInstance) GetPledgeBalance(account common.Address) (*big.Int, error) {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewProxyProof(ins.proofProxyAddr, client)
	if err != nil {
		return nil, err
	}

	amount, err := proofIns.Bal(&bind.CallOpts{}, account)
	return amount, err
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

func (ins *ProofInstance) FilterSubmitProof(opt *bind.FilterOpts, submitters []common.Address, rnds [][32]byte) ([]SubmitProofEvent, error) {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewIFileProof(ins.proofAddr, client)
	if err != nil {
		return nil, err
	}

	proofIter, err := proofIns.FilterSubmitProof(opt, submitters, rnds)
	if err != nil {
		return nil, err
	}
	defer proofIter.Close()

	var proofs []SubmitProofEvent
	var rnd fr.Element
	for proofIter.Next() {
		rnd.SetBytes(proofIter.Event.Rnd[:])
		proof := SubmitProofEvent{
			Submitter: proofIter.Event.Submitter,
			Rnd:       rnd,
			Cn:        FromSolidityG1(proofIter.Event.Cn),
			Pn:        FromSolidityProof(proofIter.Event.Pn),
			Last:      proofIter.Event.Last,
			Profit:    proofIter.Event.Profit,
			Raw:       proofIter.Event.Raw,
		}
		proofs = append(proofs, proof)
	}

	return proofs, nil
}

func (ins *ProofInstance) FilterNoProofs(opt *bind.FilterOpts) ([]NoProofsEvent, error) {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewIFileProof(ins.proofAddr, client)
	if err != nil {
		return nil, err
	}

	noProofsIter, err := proofIns.FilterNoProofs(opt)
	if err != nil {
		return nil, err
	}
	defer noProofsIter.Close()

	var noProofs []NoProofsEvent
	for noProofsIter.Next() {
		noProof := NoProofsEvent{
			OldLast:      noProofsIter.Event.OldLast,
			NewLast:      noProofsIter.Event.NewLast,
			MissedProfit: noProofsIter.Event.MisProfit,
		}
		noProofs = append(noProofs, noProof)
	}

	return noProofs, nil
}

func (ins *ProofInstance) FilterChallengeCn(opt *bind.FilterOpts, submitters []common.Address, challengers []common.Address, lasts []*big.Int) ([]ChallengeCnEvent, error) {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewIFileProof(ins.proofAddr, client)
	if err != nil {
		return nil, err
	}

	challengeIter, err := proofIns.FilterChallengeCn(opt, submitters, challengers, lasts)
	if err != nil {
		return nil, err
	}
	defer challengeIter.Close()

	var challenges []ChallengeCnEvent
	for challengeIter.Next() {
		challenge := ChallengeCnEvent{
			Submitter:      challengeIter.Event.Submitter,
			Challenger:     challengeIter.Event.Challenger,
			Last:           challengeIter.Event.Last,
			Round:          challengeIter.Event.Round,
			ChallengeIndex: challengeIter.Event.ChalIndex,
			Raw:            challengeIter.Event.Raw,
		}
		challenges = append(challenges, challenge)
	}

	return challenges, nil
}

func (ins *ProofInstance) FilterResponseChallenge(opt *bind.FilterOpts, submitters []common.Address, challengers []common.Address, lasts []*big.Int) ([]ResponseChallengeEvent, error) {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewIFileProof(ins.proofAddr, client)
	if err != nil {
		return nil, err
	}

	responseIter, err := proofIns.FilterResponseChal(opt, submitters, challengers, lasts)
	if err != nil {
		return nil, err
	}
	defer responseIter.Close()

	var responses []ResponseChallengeEvent
	for responseIter.Next() {
		response := ResponseChallengeEvent{
			Submitter:  responseIter.Event.Submitter,
			Challenger: responseIter.Event.Challenger,
			Last:       responseIter.Event.Last,
			Round:      responseIter.Event.Round,
			Raw:        responseIter.Event.Raw,
		}
		responses = append(responses, response)
	}

	return responses, nil
}

func (ins *ProofInstance) FilterChallengeResult(opt *bind.FilterOpts, submitters []common.Address, challengers []common.Address, lasts []*big.Int) ([]ChallengeResultEvent, error) {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	proofIns, err := proxyfileproof.NewIFileProof(ins.proofAddr, client)
	if err != nil {
		return nil, err
	}

	resIter, err := proofIns.FilterChallengeRes(opt, submitters, challengers, lasts)
	if err != nil {
		return nil, err
	}
	defer resIter.Close()

	var results []ChallengeResultEvent
	for resIter.Next() {
		res := ChallengeResultEvent{
			Submitter:  resIter.Event.Submitter,
			Challenger: resIter.Event.Challenger,
			Last:       resIter.Event.Last,
			Result:     resIter.Event.Res,
			Raw:        resIter.Event.Raw,
		}
		results = append(results, res)
	}

	return results, nil
}

func (ins *ProofInstance) FilterPenalize(opt *bind.FilterOpts, penalizedAccounts []common.Address, rewardedAccounts []common.Address) ([]PenalizeEvent, error) {
	client, err := ethclient.DialContext(context.TODO(), ins.endpoint)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	pledgeIns, err := proxyfileproof.NewIPledge(ins.pledgeAddr, client)
	if err != nil {
		return nil, err
	}

	peIter, err := pledgeIns.FilterPenalize(opt, penalizedAccounts, rewardedAccounts)
	if err != nil {
		return nil, err
	}
	defer peIter.Close()

	var penalizes []PenalizeEvent
	for peIter.Next() {
		penalize := PenalizeEvent{
			PenalizedAccount:   peIter.Event.From,
			RewardedAccount:    peIter.Event.To,
			RewardAmount:       peIter.Event.ToValue,
			ToFoundationAmount: peIter.Event.FoundationValue,
			Raw:                peIter.Event.Raw,
		}
		penalizes = append(penalizes, penalize)
	}

	return penalizes, nil
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

	rnd, err := proofIns.Rnd(&bind.CallOpts{})
	if err != nil {
		return false, err
	}

	submits, err := ins.FilterSubmitProof(&bind.FilterOpts{}, []common.Address{ins.transactor.From}, [][32]byte{rnd})
	if err != nil {
		return false, err
	}
	if len(submits) == 0 {
		return false, xerrors.Errorf("Have not submitted proof at current cycle")
	}

	challengeInfo, err := ins.GetChallengeInfo(ins.transactor.From)
	if err != nil {
		return false, err
	}

	if challengeInfo.Status == 0 {
		return false, xerrors.Errorf("Nobody has challenged yet")
	}

	if challengeInfo.Status != 11 {
		return false, xerrors.Errorf("The challenge is not completed")
	}

	last := submits[0].Last

	results, err := ins.FilterChallengeResult(&bind.FilterOpts{}, []common.Address{ins.transactor.From}, nil, []*big.Int{last})
	if err != nil {
		return false, err
	}

	if len(results) == 0 {
		return false, xerrors.Errorf("Filter ChallengeRes event but result is nil")
	}

	if !results[0].Result {
		return false, nil
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
