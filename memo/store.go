package memo

import "github.com/memoio/go-did/types"

type DIDController interface {
	// Create
	RegisterDID() error

	// Update
	AddVerificationMethod(vtype string, controller types.MemoDID, publicKeyHex string) error
	UpdateVerificationMethod(didUrl types.MemoDIDUrl, vtype string, publicKeyHex string) error
	DeactivateVerificationMethod(didUrl types.MemoDIDUrl) error
	// Relation ship include: authentication; assertionMethod; capabilityDelegation; recovery
	AddRelationShip(relationType int, didUrl types.MemoDIDUrl, expireTime int64) error
	DeactivateRelationShip(relationType int, didUrl types.MemoDIDUrl) error

	// Update mfile-did
	BuyReadPermission(did types.MfileDID) error

	// Delete
	DeactivateDID() error
}

type DIDResolver interface {
	// Read
	Resolve(didString string) (*types.MemoDIDDocument, error)
	Dereference(didUrlString string) ([]types.PublicKey, error)
}
