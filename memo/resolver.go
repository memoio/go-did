package memo

import (
	"context"
	"encoding/hex"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/ethclient"
	com "github.com/memoio/contractsv2/common"
	inst "github.com/memoio/contractsv2/go_contracts/instance"
	"github.com/memoio/did-solidity/go-contracts/proxy"
	"github.com/memoio/go-did/types"
	"golang.org/x/xerrors"
)

var DefaultContext = "https://www.w3.org/ns/did/v1"

type MemoDIDResolver struct {
	endpoint    string
	accountAddr common.Address
}

var _ DIDResolver = &MemoDIDResolver{}

func NewMemoDIDResolver(chain string) (*MemoDIDResolver, error) {
	if chain == "" {
		chain = com.DevChain
	}

	instanceAddr, endpoint := com.GetInsEndPointByChain(chain)

	client, err := ethclient.DialContext(context.TODO(), endpoint)
	if err != nil {
		return nil, err
	}

	// new instanceIns
	instanceIns, err := inst.NewInstance(instanceAddr, client)
	if err != nil {
		return nil, err
	}

	accountAddr, err := instanceIns.Instances(&bind.CallOpts{}, com.TypeAccountDid)
	if err != nil {
		return nil, err
	}

	return &MemoDIDResolver{
		endpoint:    endpoint,
		accountAddr: accountAddr,
	}, nil
}

func (r *MemoDIDResolver) GetMasterKey(didString string) (string, error) {
	did, err := types.ParseMemoDID(didString)
	if err != nil {
		return "", err
	}

	client, err := ethclient.DialContext(context.TODO(), r.endpoint)
	if err != nil {
		return "", err
	}
	defer client.Close()

	accountIns, err := proxy.NewIAccountDid(r.accountAddr, client)
	if err != nil {
		return "", err
	}

	address, err := accountIns.GetMasterKeyAddr(&bind.CallOpts{}, did.Identifier)

	return address.Hex(), err
}

func (r *MemoDIDResolver) Resolve(didString string) (*types.MemoDIDDocument, error) {
	did, err := types.ParseMemoDID(didString)
	if err != nil {
		return nil, err
	}

	client, err := ethclient.DialContext(context.TODO(), r.endpoint)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	accountIns, err := proxy.NewIAccountDid(r.accountAddr, client)
	if err != nil {
		return nil, err
	}

	dactivated, err := accountIns.IsDeactivated(&bind.CallOpts{}, did.Identifier)
	if err != nil {
		return nil, err
	}
	if dactivated {
		return &types.MemoDIDDocument{}, nil
	}

	verificationMethods, err := QueryAllVerificationMethod(accountIns, *did)
	if err != nil {
		return nil, err
	}
	authentications, _, err := QueryAllAuthtication(accountIns, *did)
	if err != nil {
		return nil, err
	}
	assertions, _, err := QueryAllAssertion(accountIns, *did)
	if err != nil {
		return nil, err
	}
	delegation, _, err := QueryAllDelagation(accountIns, *did)
	if err != nil {
		return nil, err
	}
	recovery, _, err := QueryAllRecovery(accountIns, *did)
	if err != nil {
		return nil, err
	}

	return &types.MemoDIDDocument{
		Context:              DefaultContext,
		ID:                   *did,
		VerificationMethod:   verificationMethods,
		Authentication:       authentications,
		AssertionMethod:      assertions,
		CapabilityDelegation: delegation,
		Recovery:             recovery,
	}, nil
}

func (r *MemoDIDResolver) Dereference(didUrlString string) ([]types.PublicKey, error) {
	didUrl, err := types.ParseMemoDIDUrl(didUrlString)
	if err != nil {
		return nil, err
	}

	client, err := ethclient.DialContext(context.TODO(), r.endpoint)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	accountIns, err := proxy.NewIAccountDid(r.accountAddr, client)
	if err != nil {
		return nil, err
	}

	var keys []types.PublicKey
	switch didUrl.Fragment {
	case "authentication":
		_, keys, err = QueryAllAuthtication(accountIns, didUrl.DID())
	case "assertion":
		_, keys, err = QueryAllAssertion(accountIns, didUrl.DID())
	case "delegation":
		_, keys, err = QueryAllDelagation(accountIns, didUrl.DID())
	case "recovery":
		_, keys, err = QueryAllRecovery(accountIns, didUrl.DID())
	default:
		verifyMethod, err := accountIns.GetVeri(&bind.CallOpts{}, didUrl.Identifier, big.NewInt(int64(didUrl.GetMethodIndex())))
		if err == nil && verifyMethod.Deactivated {
			return nil, xerrors.Errorf("The Verify Method(%s) is Deactivated", didUrl.String())
		}

		keys = append(keys, types.PublicKey{
			Type:         verifyMethod.MethodType,
			PublicKeyHex: hexutil.Encode(verifyMethod.PubKeyData),
		})
	}

	return keys, err
}

func QueryAllVerificationMethod(accountIns *proxy.IAccountDid, did types.MemoDID) ([]types.VerificationMethod, error) {
	size, err := accountIns.GetVeriLen(&bind.CallOpts{}, did.Identifier)
	if err != nil {
		return nil, err
	}

	var verificationMethods []types.VerificationMethod
	for i := int64(0); i < size.Int64(); i++ {
		verificationMethodSol, err := accountIns.GetVeri(&bind.CallOpts{}, did.Identifier, big.NewInt(i))
		if err != nil {
			return nil, err
		}
		if !verificationMethodSol.Deactivated {
			verificationMethod, err := types.FromSolityData(did, i, &verificationMethodSol)
			if err != nil {
				return nil, err
			}
			verificationMethods = append(verificationMethods, *verificationMethod)
		}
	}

	return verificationMethods, nil
}

func QueryAllAuthtication(accountIns *proxy.IAccountDid, did types.MemoDID) ([]types.MemoDIDUrl, []types.PublicKey, error) {
	authIter, err := accountIns.FilterAddAuth(&bind.FilterOpts{}, []string{did.Identifier})
	if err != nil {
		return nil, nil, err
	}
	defer authIter.Close()

	var authentications []types.MemoDIDUrl
	var keys []types.PublicKey
	for authIter.Next() {
		// if hex.EncodeToString(authIter.Event.Did[:]) != did.Identifier {
		// 	return nil, xerrors.Errorf("Got wrong did when query authentication")
		// }

		// parse method id
		didUrl, err := types.ParseMemoDIDUrl(authIter.Event.Id)
		if err != nil {
			return nil, nil, err
		}

		// check method id is activated or not
		activated, err := accountIns.InAuth(&bind.CallOpts{}, did.Identifier, didUrl.String())
		if err != nil {
			return nil, nil, err
		}
		verificationMethod, err := accountIns.GetVeri(&bind.CallOpts{}, didUrl.DID().Identifier, big.NewInt(int64(didUrl.GetMethodIndex())))
		if err != nil {
			return nil, nil, err
		}
		if activated && !verificationMethod.Deactivated {
			authentications = append(authentications, *didUrl)
			keys = append(keys, types.PublicKey{
				Type:         verificationMethod.MethodType,
				PublicKeyHex: hex.EncodeToString(verificationMethod.PubKeyData),
			})
		}
	}

	return authentications, keys, nil
}

// func QueryAuthtications(accountIns *proxy.IAccountDid, opt *bind.FilterOpts) ([]types.MemoDIDUrl, []types.PublicKey, error) {
// 	authIter, err := accountIns.FilterAddAuth(opt, nil)
// 	if err != nil {
// 		return nil, nil, err
// 	}
// 	defer authIter.Close()

// 	var authentications []types.MemoDIDUrl
// 	var keys []types.PublicKey
// 	for authIter.Next() {
// 		// if hex.EncodeToString(authIter.Event.Did[:]) != did.Identifier {
// 		// 	return nil, xerrors.Errorf("Got wrong did when query authentication")
// 		// }

// 		// parse method id
// 		didUrl, err := types.ParseMemoDIDUrl(authIter.Event.Id)
// 		if err != nil {
// 			return nil, nil, err
// 		}

// 		// check method id is activated or not
// 		activated, err := accountIns.InAuth(&bind.CallOpts{}, did.Identifier, didUrl.String())
// 		if err != nil {
// 			return nil, nil, err
// 		}
// 		verificationMethod, err := accountIns.GetVeri(&bind.CallOpts{}, didUrl.DID().Identifier, big.NewInt(int64(didUrl.GetMethodIndex())))
// 		if err != nil {
// 			return nil, nil, err
// 		}
// 		if activated && !verificationMethod.Deactivated {
// 			authentications = append(authentications, *didUrl)
// 			keys = append(keys, types.PublicKey{
// 				Type:         verificationMethod.MethodType,
// 				PublicKeyHex: hex.EncodeToString(verificationMethod.PubKeyData),
// 			})
// 		}
// 	}

// 	return authentications, keys, nil
// }

func QueryAllAssertion(accountIns *proxy.IAccountDid, did types.MemoDID) ([]types.MemoDIDUrl, []types.PublicKey, error) {
	assertionIter, err := accountIns.FilterAddAssertion(&bind.FilterOpts{}, []string{did.Identifier})
	if err != nil {
		return nil, nil, err
	}
	defer assertionIter.Close()

	var assertions []types.MemoDIDUrl
	var keys []types.PublicKey
	for assertionIter.Next() {
		// if hex.EncodeToString(assertionIter.Event.Did[:]) != did.Identifier {
		// 	return nil, xerrors.Errorf("Got wrong did when query assertion")
		// }

		// parse method id
		didUrl, err := types.ParseMemoDIDUrl(assertionIter.Event.Id)
		if err != nil {
			return nil, nil, err
		}

		// check method id is activated or not
		activated, err := accountIns.InAssertion(&bind.CallOpts{}, did.Identifier, didUrl.String())
		if err != nil {
			return nil, nil, err
		}
		verificationMethod, err := accountIns.GetVeri(&bind.CallOpts{}, didUrl.DID().Identifier, big.NewInt(int64(didUrl.GetMethodIndex())))
		if err != nil {
			return nil, nil, err
		}
		if activated && !verificationMethod.Deactivated {
			assertions = append(assertions, *didUrl)
			keys = append(keys, types.PublicKey{
				Type:         verificationMethod.MethodType,
				PublicKeyHex: hex.EncodeToString(verificationMethod.PubKeyData),
			})
		}
	}

	return assertions, keys, nil
}

func QueryAllDelagation(accountIns *proxy.IAccountDid, did types.MemoDID) ([]types.MemoDIDUrl, []types.PublicKey, error) {
	delegationIter, err := accountIns.FilterAddDelegation(&bind.FilterOpts{}, []string{did.Identifier})
	if err != nil {
		return nil, nil, err
	}
	defer delegationIter.Close()

	var delegations []types.MemoDIDUrl
	var keys []types.PublicKey
	for delegationIter.Next() {
		// if hex.EncodeToString(delegationIter.Event.Did[:]) != did.Identifier {
		// 	return nil, xerrors.Errorf("Got wrong did when query delegation")
		// }

		// parse method id
		didUrl, err := types.ParseMemoDIDUrl(delegationIter.Event.Id)
		if err != nil {
			return nil, nil, err
		}

		// check delegation id is expired or not
		expiration, err := accountIns.InDelegation(&bind.CallOpts{}, did.Identifier, didUrl.String())
		if err != nil {
			return nil, nil, err
		}
		verificationMethod, err := accountIns.GetVeri(&bind.CallOpts{}, didUrl.DID().Identifier, big.NewInt(int64(didUrl.GetMethodIndex())))
		if err != nil {
			return nil, nil, err
		}
		if expiration.Int64() >= time.Now().Unix() && !verificationMethod.Deactivated {
			delegations = append(delegations, *didUrl)
			keys = append(keys, types.PublicKey{
				Type:         verificationMethod.MethodType,
				PublicKeyHex: hex.EncodeToString(verificationMethod.PubKeyData),
			})
		}
	}

	return delegations, keys, nil
}

func QueryAllRecovery(accountIns *proxy.IAccountDid, did types.MemoDID) ([]types.MemoDIDUrl, []types.PublicKey, error) {
	recoveryIter, err := accountIns.FilterAddRecovery(&bind.FilterOpts{}, []string{did.Identifier})
	if err != nil {
		return nil, nil, err
	}
	defer recoveryIter.Close()

	var recovery []types.MemoDIDUrl
	var keys []types.PublicKey
	for recoveryIter.Next() {
		// if hex.EncodeToString(recoveryIter.Event.Did[:]) != did.Identifier {
		// 	return nil, xerrors.Errorf("Got wrong did when query recovery")
		// }

		// parse method id
		didUrl, err := types.ParseMemoDIDUrl(recoveryIter.Event.Recovery)
		if err != nil {
			return nil, nil, err
		}

		// check method id is activated or not
		activated, err := accountIns.InRecovery(&bind.CallOpts{}, did.Identifier, didUrl.String())
		if err != nil {
			return nil, nil, err
		}
		verificationMethod, err := accountIns.GetVeri(&bind.CallOpts{}, didUrl.DID().Identifier, big.NewInt(int64(didUrl.GetMethodIndex())))
		if err != nil {
			return nil, nil, err
		}
		if activated && !verificationMethod.Deactivated {
			recovery = append(recovery, *didUrl)
			keys = append(keys, types.PublicKey{
				Type:         verificationMethod.MethodType,
				PublicKeyHex: hex.EncodeToString(verificationMethod.PubKeyData),
			})
		}
	}

	return recovery, keys, nil
}
