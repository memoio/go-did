package mfile

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	etypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	com "github.com/memoio/contractsv2/common"
	inst "github.com/memoio/contractsv2/go_contracts/instance"
	"github.com/memoio/did-solidity/go-contracts/proxy"
	"github.com/memoio/go-did/types"
	"golang.org/x/xerrors"
)

var (
	checkTxSleepTime = 6 // wait 6s(blocktime + 1s)
	nextBlockTime    = 5 // blocktime
)

type MfileDIDController struct {
	did           *types.MfileDID
	endpoint      string
	privateKey    *ecdsa.PrivateKey
	didTransactor *bind.TransactOpts
	proxyAddr     common.Address
}

var _ MfileStore = &MfileDIDController{}

func NewMfileDIDController(privateKey *ecdsa.PrivateKey, chain, didString string) (*MfileDIDController, error) {
	instanceAddr, endpoint := com.GetInsEndPointByChain(chain)

	client, err := ethclient.DialContext(context.TODO(), endpoint)
	if err != nil {
		return nil, err
	}

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		chainID = big.NewInt(985)
	}

	// new instanceIns
	instanceIns, err := inst.NewInstance(instanceAddr, client)
	if err != nil {
		return nil, err
	}

	// get proxyAddr
	proxyAddr, err := instanceIns.Instances(&bind.CallOpts{}, com.TypeDidProxy)
	if err != nil {
		return nil, err
	}

	// new auth
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
	if err != nil {
		return nil, err
	}
	auth.Value = big.NewInt(0)     // in wei
	auth.GasLimit = uint64(300000) // in units
	auth.GasPrice = big.NewInt(1000)

	did, err := types.ParseMfileDID(didString)
	return &MfileDIDController{
		did:           did,
		endpoint:      endpoint,
		privateKey:    privateKey,
		didTransactor: auth,
		proxyAddr:     proxyAddr,
	}, err
}

func (c *MfileDIDController) DID() *types.MfileDID {
	return c.did
}

func (c *MfileDIDController) RegisterDID(encode string, ftype uint8, price *big.Int, keywords []string, controller types.MemoDID) error {
	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proxyIns, err := proxy.NewProxy(c.proxyAddr, client)
	if err != nil {
		return err
	}

	tx, err := proxyIns.RegisterMfileDid(c.didTransactor, c.did.Identifier, encode, ftype, controller.Identifier, price, keywords)
	if err != nil {
		return err
	}

	return CheckTx(c.endpoint, tx.Hash(), "RegisterDID")
}

func (c *MfileDIDController) ChangeController(controller types.MemoDID) error {
	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proxyIns, err := proxy.NewProxy(c.proxyAddr, client)
	if err != nil {
		return err
	}

	tx, err := proxyIns.ChangeController(c.didTransactor, c.did.Identifier, controller.Identifier)
	if err != nil {
		return err
	}

	return CheckTx(c.endpoint, tx.Hash(), "ChangeController")
}

func (c *MfileDIDController) ChangeFileType(ftype uint8) error {
	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proxyIns, err := proxy.NewProxy(c.proxyAddr, client)
	if err != nil {
		return err
	}

	tx, err := proxyIns.ChangeFtype(c.didTransactor, c.did.Identifier, ftype)
	if err != nil {
		return err
	}

	return CheckTx(c.endpoint, tx.Hash(), "ChangeFileType")
}

func (c *MfileDIDController) ChangePrice(price *big.Int) error {
	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proxyIns, err := proxy.NewProxy(c.proxyAddr, client)
	if err != nil {
		return err
	}

	tx, err := proxyIns.ChangePrice(c.didTransactor, c.did.Identifier, price)
	if err != nil {
		return err
	}

	return CheckTx(c.endpoint, tx.Hash(), "ChangePrice")
}

func (c *MfileDIDController) ChangeKeywords(keywords []string) error {
	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proxyIns, err := proxy.NewProxy(c.proxyAddr, client)
	if err != nil {
		return err
	}

	tx, err := proxyIns.ChangeKeywords(c.didTransactor, c.did.Identifier, keywords)
	if err != nil {
		return err
	}

	return CheckTx(c.endpoint, tx.Hash(), "ChangeKeywords")
}

func (c *MfileDIDController) AddRelationShip(relationType int, did types.MemoDID) error {
	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proxyIns, err := proxy.NewProxy(c.proxyAddr, client)
	if err != nil {
		return err
	}

	var tx *etypes.Transaction
	switch relationType {
	case types.Read:
		tx, err = proxyIns.GrantRead(c.didTransactor, c.did.Identifier, did.Identifier)
	default:
		return xerrors.Errorf("unsupported relation ships")
	}
	if err != nil {
		return err
	}

	return CheckTx(c.endpoint, tx.Hash(), "AddRelationShip")
}

func (c *MfileDIDController) DeactivateRelationShip(relationType int, didUrl types.MemoDID) error {
	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proxyIns, err := proxy.NewProxy(c.proxyAddr, client)
	if err != nil {
		return err
	}

	var tx *etypes.Transaction
	switch relationType {
	case types.Read:
		tx, err = proxyIns.DeactivateRead(c.didTransactor, c.did.Identifier, didUrl.Identifier)
	default:
		return xerrors.Errorf("unsupported relation ships")
	}
	if err != nil {
		return err
	}

	return CheckTx(c.endpoint, tx.Hash(), "DactivateRelationShip")
}

func (c *MfileDIDController) DeactivateDID() error {
	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proxyIns, err := proxy.NewProxy(c.proxyAddr, client)
	if err != nil {
		return err
	}

	tx, err := proxyIns.DeactivateMfileDid(c.didTransactor, c.did.Identifier, true)
	if err != nil {
		return err
	}

	return CheckTx(c.endpoint, tx.Hash(), "DeactivateDID")
}

func CheckTx(endPoint string, txHash common.Hash, name string) error {
	var receipt *etypes.Receipt

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
