package mfile

import (
	"context"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	com "github.com/memoio/contractsv2/common"
	inst "github.com/memoio/contractsv2/go_contracts/instance"
	"github.com/memoio/did-solidity/go-contracts/proxy"
	"github.com/memoio/go-did/types"
)

var DefaultContext = "https://www.w3.org/ns/did/v1"

type MfileDIDResolver struct {
	endpoint    string
	accountAddr common.Address
}

func NewMfileDIDResolver(chain string) (*MfileDIDResolver, error) {
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

	accountAddr, err := instanceIns.Instances(&bind.CallOpts{}, com.TypeFileDid)
	if err != nil {
		return nil, err
	}

	return &MfileDIDResolver{
		endpoint:    endpoint,
		accountAddr: accountAddr,
	}, nil
}

func (r *MfileDIDResolver) Resolve(didString string) (*types.MfileDIDDocument, error) {
	did, err := types.ParseMfileDID(didString)
	if err != nil {
		return nil, err
	}

	client, err := ethclient.DialContext(context.TODO(), r.endpoint)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	accountIns, err := proxy.NewIFileDid(r.accountAddr, client)
	if err != nil {
		return nil, err
	}

	deactivated, err := accountIns.Deactivated(&bind.CallOpts{}, did.Identifier)
	if err != nil {
		return nil, err
	}
	if deactivated {
		return &types.MfileDIDDocument{}, nil
	}

	encode, err := accountIns.GetEncode(&bind.CallOpts{}, did.Identifier)
	if err != nil {
		return nil, err
	}

	ftype, err := accountIns.GetFtype(&bind.CallOpts{}, did.Identifier)
	if err != nil {
		return nil, err
	}
	var ftypeString string
	if ftype == 0 {
		ftypeString = "private"
	} else {
		ftypeString = "public"
	}

	price, err := accountIns.GetPrice(&bind.CallOpts{}, did.Identifier)
	if err != nil {
		return nil, err
	}

	keywords, err := accountIns.GetKeywords(&bind.CallOpts{}, did.Identifier)
	if err != nil {
		return nil, err
	}

	controller, err := accountIns.GetController(&bind.CallOpts{}, did.Identifier)
	if err != nil {
		return nil, err
	}
	ctr, err := types.ParseMemoDID("did:memo:" + controller)
	if err != nil {
		ctr = &types.MemoDID{Method: "memo"}
	}

	read, err := QueryAllRead(accountIns, did)
	if err != nil {
		return nil, err
	}

	return &types.MfileDIDDocument{
		Context:    DefaultContext,
		ID:         *did,
		Type:       ftypeString,
		Encode:     encode,
		Price:      price.Int64(),
		Keywords:   keywords,
		Controller: *ctr,
		Read:       read,
	}, nil
}

func QueryAllRead(accountIns *proxy.IFileDid, did *types.MfileDID) ([]types.MemoDID, error) {
	var reads []types.MemoDID

	// 查询付费获取的读取权限
	readIter, err := accountIns.FilterBuyRead(&bind.FilterOpts{}, []string{did.Identifier})
	if err != nil {
		return nil, err
	}
	for readIter.Next() {
		// 目前controller只支持did:memo，因此可以无需保存前缀
		read, err := types.ParseMemoDID("did:memo:" + readIter.Event.MemoDid)
		if err != nil {
			return nil, err
			// continue
		}

		// check controller is activated or not
		activated, err := accountIns.Read(&bind.CallOpts{}, did.Identifier, read.Identifier)
		if err != nil {
			return nil, err
		}
		if activated > 0 {
			reads = append(reads, *read)
		}
	}

	// 查询由controller免费授予的读取权限
	freeReadIter, err := accountIns.FilterGrantRead(&bind.FilterOpts{}, []string{did.Identifier})
	if err != nil {
		return nil, err
	}

	for freeReadIter.Next() {
		// 目前controller只支持did:memo，因此可以无需保存前缀
		read, err := types.ParseMemoDID("did:memo:" + freeReadIter.Event.MemoDid)
		if err != nil {
			return nil, err
		}

		// check controller is activated or not
		activated, err := accountIns.Read(&bind.CallOpts{}, did.Identifier, freeReadIter.Event.MemoDid)
		if err != nil {
			return nil, err
		}
		if activated > 0 {
			reads = append(reads, *read)
		}
	}

	return reads, nil
}
