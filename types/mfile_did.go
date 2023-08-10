package types

import (
	"encoding/json"
	"strings"

	"github.com/ipfs/go-cid"
	"golang.org/x/xerrors"
)

const (
	Read int = iota
)

type MfileDID struct {
	// DID Method(mfile)
	Method string

	// The mfile-specific-id's hash method(mid, cid, md5...)
	HashMethod string

	// The mfile-specific-id component of a DID
	// mfile-specific-id = cid(file)
	Identifier string
}

func ParseMfileDID(didString string) (*MfileDID, error) {
	parts := strings.Split(didString, ":")
	if len(parts) != 3 && len(parts) != 4 {
		return nil, xerrors.Errorf("did must match the syntax: did:mfile:{cid}")
	}

	if parts[0] != "did" {
		return nil, xerrors.Errorf("did string does not begin with 'did:' prefix")
	}

	if parts[1] != "mfile" {
		return nil, xerrors.Errorf("unspport method %s", parts[1])
	}

	if len(parts) >= 4 {
		return nil, xerrors.Errorf("unsupported did format")
	} else {
		if _, err := cid.Decode(parts[len(parts)-1]); err != nil {
			return nil, xerrors.Errorf("%s is not cid", parts[2])
		}
	}
	return &MfileDID{
		Method:     parts[1],
		Identifier: parts[2],
	}, nil
}

func (d *MfileDID) String() string {
	return "did:" + d.Method + ":" + d.Identifier
}

func (d MfileDID) MarshalJSON() ([]byte, error) {
	return json.Marshal("did:" + d.Method + ":" + d.Identifier)
}

func (d *MfileDID) UnmarshalJSON(data []byte) error {
	var didString string
	err := json.Unmarshal(data, &didString)
	if err != nil {
		return err
	}
	did, err := ParseMfileDID(didString)
	if err != nil {
		return err
	}
	d.Method = did.Method
	d.Identifier = did.Identifier
	return err
}
