package proof

import (
	"context"
	"encoding/binary"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	com "github.com/memoio/contractsv2/common"
	inst "github.com/memoio/contractsv2/go_contracts/instance"
	proxyfileproof "github.com/memoio/did-solidity/go-contracts/proxy-proof"
)

type ProfitInfo struct {
	PendingProfit *big.Int
	MissedProfit  *big.Int
	FinalExpire   *big.Int
}

type ChallengeInfo struct {
	ChalStatus uint8
	Challenger common.Address
	ChalIndex  uint8
	StartIndex *big.Int
	ChalLength *big.Int
}

type SettingInfo struct {
	Interval        uint32
	Period          uint32
	ChalSum         uint32
	RespondTime     uint32
	Price           uint64
	Submitter       common.Address
	Receiver        common.Address
	Foundation      common.Address
	ChalRewardRatio uint8
	ChalPledge      *big.Int
}

type AlterSettingInfo struct {
	SettingInfo
	Vk [8][32]byte
}

func ToSolidityG1(g1 bls12381.G1Affine) [4][32]byte {
	var res [4][32]byte
	elementx := g1.X.Bytes()
	elementy := g1.Y.Bytes()

	copy(res[0][16:], elementx[:16])
	copy(res[1][:], elementx[16:])
	copy(res[2][16:], elementy[:16])
	copy(res[3][:], elementy[16:])

	return res
}

func FromSolidityG1(g1 [4][32]byte) bls12381.G1Affine {
	var res bls12381.G1Affine
	res.X.SetBytes(append(g1[0][:], g1[1][:]...))
	res.Y.SetBytes(append(g1[2][:], g1[3][:]...))

	return res
}

func ToAppendedBytesG1(g1 bls12381.G1Affine) []byte {
	res := make([]byte, 128)
	elementx := g1.X.Bytes()
	elementy := g1.Y.Bytes()

	copy(res[0:64], common.LeftPadBytes(elementx[:], 64))
	copy(res[64:128], common.LeftPadBytes(elementy[:], 64))

	return res
}

func ToSolidityG2(g2 bls12381.G2Affine) [8][32]byte {
	var res [8][32]byte
	elementx1 := g2.X.A0.Bytes()
	elementx2 := g2.X.A1.Bytes()
	elementy1 := g2.Y.A0.Bytes()
	elementy2 := g2.Y.A1.Bytes()

	copy(res[0][16:], elementx1[:16])
	copy(res[1][:], elementx1[16:])
	copy(res[2][16:], elementx2[:16])
	copy(res[3][:], elementx2[16:])
	copy(res[4][16:], elementy1[:16])
	copy(res[5][:], elementy1[16:])
	copy(res[6][16:], elementy2[:16])
	copy(res[7][:], elementy2[16:])

	return res
}

func FromSolidityG2(g2 [8][32]byte) bls12381.G2Affine {
	var res bls12381.G2Affine
	res.X.A0.SetBytes(append(g2[0][:], g2[1][:]...))
	res.X.A1.SetBytes(append(g2[2][:], g2[3][:]...))
	res.Y.A0.SetBytes(append(g2[4][:], g2[5][:]...))
	res.Y.A1.SetBytes(append(g2[6][:], g2[7][:]...))

	return res
}

func ToAppendedBytesG2(g2 bls12381.G2Affine) []byte {
	res := make([]byte, 256)
	elementx1 := g2.X.A0.Bytes()
	elementx2 := g2.X.A1.Bytes()
	elementy1 := g2.Y.A0.Bytes()
	elementy2 := g2.Y.A1.Bytes()

	copy(res[0:64], common.LeftPadBytes(elementx1[:], 64))
	copy(res[64:128], common.LeftPadBytes(elementx2[:], 64))
	copy(res[128:192], common.LeftPadBytes(elementy1[:], 64))
	copy(res[192:256], common.LeftPadBytes(elementy2[:], 64))

	return res
}

func ToSolidityProof(proof kzg.OpeningProof) proxyfileproof.IFileProofProofInfo {
	Pi := ToSolidityG1(proof.H)
	value := proof.ClaimedValue.Bytes()

	return proxyfileproof.IFileProofProofInfo{
		Npsi: Pi,
		Y:    value,
	}
}

func GetAlterSettingInfoHash(instanceAddr, authAddr common.Address, setting SettingInfo, vk bls12381.G2Affine, nonce *big.Int) []byte {
	interval := make([]byte, 4)
	period := make([]byte, 4)
	challengeSum := make([]byte, 4)
	respondTime := make([]byte, 4)
	price := make([]byte, 8)
	binary.BigEndian.PutUint32(interval, setting.Interval)
	binary.BigEndian.PutUint32(period, setting.Period)
	binary.BigEndian.PutUint32(challengeSum, setting.ChalSum)
	binary.BigEndian.PutUint32(respondTime, setting.RespondTime)
	binary.BigEndian.PutUint64(price, setting.Price)

	pledge := common.LeftPadBytes(setting.ChalPledge.Bytes(), 32)
	vkBytes := ToAppendedBytesG2(vk)

	hash := crypto.Keccak256(
		instanceAddr.Bytes(),
		[]byte("alterFileProofSetting"),
		interval,
		period,
		challengeSum,
		respondTime,
		price,
		setting.Submitter.Bytes(),
		setting.Receiver.Bytes(),
		setting.Foundation.Bytes(),
		[]byte{setting.ChalRewardRatio},
		pledge,
		vkBytes)

	m := common.LeftPadBytes(nonce.Bytes(), 32)
	hash = crypto.Keccak256(authAddr.Bytes(), m, []byte("perm"), hash)
	return hash
}

func GetCredentialHash(chain string, userAddr common.Address, commit bls12381.G1Affine, size uint64, start *big.Int, end *big.Int) ([]byte, error) {
	instanceAddr, endpoint := com.GetInsEndPointByChain(chain)

	client, err := ethclient.DialContext(context.TODO(), endpoint)
	if err != nil {
		return nil, err
	}

	// new instance
	instanceIns, err := inst.NewInstance(instanceAddr, client)
	if err != nil {
		return nil, err
	}

	proofAddr, err := instanceIns.Instances(&bind.CallOpts{}, com.TypeFileProof)
	if err != nil {
		return nil, err
	}

	sizeByte := make([]byte, 8)
	binary.BigEndian.PutUint64(sizeByte, size)
	startByte := common.LeftPadBytes(start.Bytes(), 32)
	endByte := common.LeftPadBytes(end.Bytes(), 32)
	hash := crypto.Keccak256(proofAddr.Bytes(), userAddr.Bytes(), ToAppendedBytesG1(commit), sizeByte, startByte, endByte)
	return hash, nil
}

// func GetHashByArguments(instanceAddr, authAddr common.Address, setting SettingInfo, vk bls12381.G2Affine, nonce *big.Int) []byte {
// 	addressT, _ := abi.NewType("address", "", nil)
// 	stringT, _ := abi.NewType("string", "", nil)
// 	uint8T, _ := abi.NewType("uint8", "", nil)
// 	uint32T, _ := abi.NewType("uint32", "", nil)
// 	uint64T, _ := abi.NewType("uint64", "", nil)
// 	uint256T, _ := abi.NewType("uint256", "", nil)
// 	bytes32Arr8T, _ := abi.NewType("bytes32[8]", "", nil)

// 	arguments := abi.Arguments{
// 		// instance address
// 		{
// 			Type: addressT,
// 		},
// 		// string
// 		{
// 			Type: stringT,
// 		},
// 		// interval
// 		{
// 			Type: uint32T,
// 		},
// 		// period
// 		{
// 			Type: uint32T,
// 		},
// 		// challenge sum
// 		{
// 			Type: uint32T,
// 		},
// 		// respond time
// 		{
// 			Type: uint32T,
// 		},
// 		// price
// 		{
// 			Type: uint64T,
// 		},
// 		// submitter
// 		{
// 			Type: addressT,
// 		},
// 		// receiver
// 		{
// 			Type: addressT,
// 		},
// 		// foundation
// 		{
// 			Type: addressT,
// 		},
// 		// challenge reward ratio
// 		{
// 			Type: uint8T,
// 		},
// 		{
// 			Type: uint256T,
// 		},
// 		{
// 			Type: bytes32Arr8T,
// 		},
// 	}

// 	data, err := arguments.Pack(
// 		instanceAddr,
// 		"alterFileProofSetting",
// 		setting.Interval,
// 		setting.Period,
// 		setting.ChalSum,
// 		setting.RespondTime,
// 		setting.Price,
// 		setting.Submitter,
// 		setting.Receiver,
// 		setting.Foundation,
// 		setting.ChalRewardRatio,
// 		setting.ChalPledge,
// 		ToSolidityG2(vk))
// 	if err != nil {
// 		log.Println(err.Error())
// 		return nil
// 	}
// 	log.Println(data)

// 	return data
// }
