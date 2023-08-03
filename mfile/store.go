package mfile

import (
	"math/big"

	"github.com/memoio/go-did/types"
)

type MfileStore interface {
	RegisterDID(encode string, ftype uint8, price *big.Int, keywords []string, controller types.MemoDID) error

	ChangeController(controller types.MemoDID) error
	ChangeFileType(ftype uint8) error
	ChangePrice(price *big.Int) error
	ChangeKeywords(keywords []string) error
	// Relation ship include: read
	AddRelationShip(relationType int, did types.MemoDID) error
	DeactivateRelationShip(relationType int, didUrl types.MemoDID) error

	DeactivateDID() error
}

type MfileResolver interface {
	Resolve(didString string) error
	CanRead(didString string) error
}
