package memo

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	etypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/memoio/go-did/types"
	"golang.org/x/xerrors"

	com "github.com/memoio/contractsv2/common"
	"github.com/memoio/contractsv2/go_contracts/erc"
	inst "github.com/memoio/contractsv2/go_contracts/instance"
	"github.com/memoio/did-solidity/go-contracts/proxy"
)

var (
	checkTxSleepTime = 6 // wait 6s
	nextBlockTime    = 5 // blocktime
)

type MemoDIDController struct {
	did           *types.MemoDID
	instanceAddr  common.Address
	endpoint      string
	privateKey    *ecdsa.PrivateKey
	didTransactor *bind.TransactOpts
	proxyAddr     common.Address
}

var _ DIDController = &MemoDIDController{}

func NewMemoDIDController(privateKey *ecdsa.PrivateKey, chain string) (*MemoDIDController, error) {
	did, err := CreatMemoDID(privateKey, chain)
	if err != nil {
		return nil, err
	}
	controller, err := NewMemoDIDControllerWithDID(privateKey, chain, did.String())
	return controller, err
}

func NewMemoDIDControllerWithDID(privateKey *ecdsa.PrivateKey, chain, didString string) (*MemoDIDController, error) {
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
	// auth.GasPrice = big.NewInt(1000)

	did, err := types.ParseMemoDID(didString)
	return &MemoDIDController{
		did:           did,
		instanceAddr:  instanceAddr,
		endpoint:      endpoint,
		privateKey:    privateKey,
		didTransactor: auth,
		proxyAddr:     proxyAddr,
	}, err
}

// Create unregistered DID
func CreatMemoDID(privateKey *ecdsa.PrivateKey, chain string) (*types.MemoDID, error) {
	_, endpoint := com.GetInsEndPointByChain(chain)
	client, err := ethclient.DialContext(context.TODO(), endpoint)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, xerrors.Errorf("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}
	address := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := client.PendingNonceAt(context.TODO(), address)
	if err != nil {
		return nil, err
	}

	identifier := hex.EncodeToString(crypto.Keccak256(binary.AppendUvarint(address.Bytes(), nonce)))

	return &types.MemoDID{
		Method:      "memo",
		Identifier:  identifier,
		Identifiers: []string{identifier},
	}, nil
}

func (c *MemoDIDController) DID() *types.MemoDID {
	return c.did
}

func (c *MemoDIDController) RegisterDID() error {
	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proxyIns, err := proxy.NewProxy(c.proxyAddr, client)
	if err != nil {
		return err
	}

	// Get public key from private key
	publicKey := c.privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return xerrors.Errorf("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}
	publicKeyBytes := crypto.CompressPubkey(publicKeyECDSA)

	tx, err := proxyIns.CreateDID(c.didTransactor, c.did.Identifier, "EcdsaSecp256k1VerificationKey2019", publicKeyBytes)
	if err != nil {
		return err
	}

	return CheckTx(c.endpoint, tx.Hash(), "RegisterDID")
}

func (c *MemoDIDController) AddVerificationMethod(vtype string, controller types.MemoDID, publicKeyHex string) error {
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return err
	}

	publicKey := proxy.IAccountDidPublicKey{
		MethodType:  vtype,
		Controller:  controller.Identifier,
		PubKeyData:  publicKeyBytes,
		Deactivated: false,
	}

	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proxyIns, err := proxy.NewProxy(c.proxyAddr, client)
	if err != nil {
		return err
	}

	tx, err := proxyIns.AddVeri(c.didTransactor, c.did.Identifier, publicKey)
	if err != nil {
		return err
	}

	return CheckTx(c.endpoint, tx.Hash(), "AddVerificationMethod")
}

func (c *MemoDIDController) UpdateVerificationMethod(didUrl types.MemoDIDUrl, vtype string, publicKeyHex string) error {
	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proxyIns, err := proxy.NewProxy(c.proxyAddr, client)
	if err != nil {
		return err
	}

	tx, err := proxyIns.UpdateVeri(c.didTransactor, didUrl.Identifier, big.NewInt(int64(didUrl.GetMethodIndex())), vtype, []byte(publicKeyHex))
	if err != nil {
		return err
	}
	return CheckTx(c.endpoint, tx.Hash(), "UpdateVerificationMethod")
}

func (c *MemoDIDController) DeactivateVerificationMethod(didUrl types.MemoDIDUrl) error {
	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proxyIns, err := proxy.NewProxy(c.proxyAddr, client)
	if err != nil {
		return err
	}

	tx, err := proxyIns.DeactivateVeri(c.didTransactor, didUrl.Identifier, big.NewInt(int64(didUrl.GetMethodIndex())), true)
	if err != nil {
		return err
	}

	return CheckTx(c.endpoint, tx.Hash(), "DeactivateVerificationMethod")
}

func (c *MemoDIDController) AddRelationShip(relationType int, didUrl types.MemoDIDUrl, expireTime int64) error {
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
	case types.Authentication:
		tx, err = proxyIns.AddAuth(c.didTransactor, c.did.Identifier, didUrl.String())
	case types.AssertionMethod:
		tx, err = proxyIns.AddAssertion(c.didTransactor, c.did.Identifier, didUrl.String())
	case types.CapabilityDelegation:
		tx, err = proxyIns.AddDelegation(c.didTransactor, c.did.Identifier, didUrl.String(), big.NewInt(expireTime+time.Now().Unix()))
	case types.Recovery:
		tx, err = proxyIns.AddRecovery(c.didTransactor, c.did.Identifier, didUrl.String())
	default:
		return xerrors.Errorf("unsupported relation ships")
	}
	if err != nil {
		return err
	}

	return CheckTx(c.endpoint, tx.Hash(), "AddRelationShip")
}

func (c *MemoDIDController) DeactivateRelationShip(relationType int, didUrl types.MemoDIDUrl) error {
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
	case types.Authentication:
		tx, err = proxyIns.RemoveAuth(c.didTransactor, c.did.Identifier, didUrl.String())
	case types.AssertionMethod:
		tx, err = proxyIns.RemoveAssertion(c.didTransactor, c.did.Identifier, didUrl.String())
	case types.CapabilityDelegation:
		tx, err = proxyIns.RemoveDelegation(c.didTransactor, c.did.Identifier, didUrl.String())
	case types.Recovery:
		tx, err = proxyIns.RemoveRecovery(c.didTransactor, c.did.Identifier, didUrl.String())
	default:
		return xerrors.Errorf("unsupported relation ships")
	}
	if err != nil {
		return err
	}

	return CheckTx(c.endpoint, tx.Hash(), "DeactivateRelationShip")
}

func (c *MemoDIDController) ApproveOfMfileContract(amount int) error {
	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	instanceIns, err := inst.NewInstance(c.instanceAddr, client)
	if err != nil {
		return err
	}

	// get fileDIDCtrAddr
	fileDIDCtrAddr, err := instanceIns.Instances(&bind.CallOpts{}, com.TypeFileDidControl)
	if err != nil {
		return err
	}

	// get ERC20Addr
	ERC20Addr, err := instanceIns.Instances(&bind.CallOpts{}, com.TypeERC20)
	if err != nil {
		return err
	}

	// get ERC20Ins
	ERC20Ins, err := erc.NewERC20(ERC20Addr, client)
	if err != nil {
		return err
	}

	tx, err := ERC20Ins.Approve(c.didTransactor, fileDIDCtrAddr, big.NewInt(int64(amount)))
	if err != nil {
		return err
	}

	return CheckTx(c.endpoint, tx.Hash(), "ApproveOfMfileContract")
}

func (c *MemoDIDController) BuyReadPermission(did types.MfileDID) error {
	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proxyIns, err := proxy.NewProxy(c.proxyAddr, client)
	if err != nil {
		return err
	}

	tx, err := proxyIns.BuyRead(c.didTransactor, did.Identifier, c.did.Identifier)
	if err != nil {
		return err
	}

	return CheckTx(c.endpoint, tx.Hash(), "BuyReadPermission")
}

func (c *MemoDIDController) DeactivateDID() error {
	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proxyIns, err := proxy.NewProxy(c.proxyAddr, client)
	if err != nil {
		return err
	}

	tx, err := proxyIns.DeactivateDID(c.didTransactor, c.did.Identifier, true)
	if err != nil {
		return err
	}

	return CheckTx(c.endpoint, tx.Hash(), "DeactivateDID")
}

// CheckTx check whether transaction is successful through receipt
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
