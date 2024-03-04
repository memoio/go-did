package proof

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	proxyfileproof "github.com/memoio/did-solidity/go-contracts/proxy-proof"
)

// func FromSolidityG1(g1 [4][32]byte) bls12381.G1Affine {

// }

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

// func FromSolidityProof(proof pr.FileProofProofInfo) kzg.OpeningProof {

// }

func ToSolidityProof(proof kzg.OpeningProof) proxyfileproof.IFileProofProofInfo {
	Pi := ToSolidityG1(proof.H)
	value := proof.ClaimedValue.Bytes()

	return proxyfileproof.IFileProofProofInfo{
		Npsi: Pi,
		Y:    value,
	}
}
