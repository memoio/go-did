package types

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/nuts-foundation/did-ockam"
	"golang.org/x/xerrors"
)

const (
	Authentication int = iota
	AssertionMethod
	CapabilityDelegation
	Recovery
)

var supportFrangment = []string{"authentication", "assertion", "delegation", "recovery", "masterKey"}

type MemoDID struct {
	// DID Method(memo)
	Method string

	// The memo-specific-id component of a DID
	// memo-specific-id = hex(hash(address, nonce))
	Identifier string

	// memo-specific-id may be composed of multiple `:` separated idstrings
	// for example: did:memo:{chainID}:ce5ac89f84530a1cf2cdee5a0643045a8b0a4995b1c765ba289d7859cfb1193e
	Identifiers []string
}

// Parse parses the input string into a DID structure.
func ParseMemoDID(didString string) (*MemoDID, error) {
	did, err := did.Parse(didString)
	if err != nil {
		return nil, err
	}
	if did.IsURL() {
		return nil, xerrors.Errorf("%s is did url", didString)
	}
	if did.Method != "memo" {
		return nil, xerrors.Errorf("unsupported method %s", did.Method)
	}
	if len(did.IDStrings) > 1 {
		// TODO: check didString[2:len(didStrings)-1] ==? {chain id}
		return nil, xerrors.Errorf("TODO: support chain id")
	}
	if isNot32ByteHex(did.IDStrings[len(did.IDStrings)-1]) {
		return nil, xerrors.Errorf("%s is not 32 byte hex string", did.IDStrings[len(did.IDStrings)-1])
	}
	return &MemoDID{
		Method:      "memo",
		Identifier:  did.ID,
		Identifiers: did.IDStrings,
	}, nil
}

func (d *MemoDID) String() string {
	return "did:" + d.Method + ":" + d.Identifier
}

func (d MemoDID) MarshalJSON() ([]byte, error) {
	if d.Identifier == "" {
		d.Identifier = strings.Join(d.Identifiers, ":")
	}
	didString := "did:" + d.Method + ":" + d.Identifier
	return json.Marshal(didString)
}

func (d *MemoDID) UnmarshalJSON(data []byte) error {
	var didString string
	err := json.Unmarshal(data, &didString)
	if err != nil {
		return err
	}
	did, err := ParseMemoDID(didString)
	if err != nil {
		return err
	}
	d.Method = did.Method
	d.Identifier = did.Identifier
	d.Identifiers = did.Identifiers
	return err
}

func (d *MemoDID) DIDUrl(methodIndex int64) (MemoDIDUrl, error) {
	var id MemoDIDUrl
	if methodIndex < 0 {
		return MemoDIDUrl{}, xerrors.Errorf("method index cannot be less than 0")
	} else if methodIndex == 0 {
		id = MemoDIDUrl{
			Method:      d.Method,
			Identifier:  d.Identifier,
			Identidiers: d.Identifiers,
			Fragment:    "masterKey",
		}
	} else {
		id = MemoDIDUrl{
			Method:      d.Method,
			Identifier:  d.Identifier,
			Identidiers: d.Identifiers,
			Fragment:    fmt.Sprintf("key-%d", methodIndex),
		}
	}

	return id, nil
}

type MemoDIDUrl struct {
	// DID Method(memo)
	Method string

	// The memo-specific-id component of a DID
	// memo-specific-id = hex(hash(address, nonce))
	Identifier string

	// memo-specific-id may be composed of multiple `:` separated idstrings
	// for example: did:memo:{chainID}:ce5ac89f84530a1cf2cdee5a0643045a8b0a4995b1c765ba289d7859cfb1193e
	Identidiers []string

	// DID Fragment, the portion of a DID reference that follows the first character ("#")
	// support fragment: masterKey, key-{i}
	Fragment string
}

func ParseMemoDIDUrl(didUrl string) (*MemoDIDUrl, error) {
	did, err := did.Parse(didUrl)
	if err != nil {
		return nil, err
	}
	if !did.IsURL() {
		return nil, xerrors.Errorf("%s is not did url", didUrl)
	}
	if did.Method != "memo" {
		return nil, xerrors.Errorf("unsupported method %s", did.Method)
	}
	if len(did.IDStrings) > 1 {
		// TODO: check didString[2:len(didStrings)-1] ==? {chain id}
		return nil, xerrors.Errorf("TODO: support chain id")
	}
	if isNot32ByteHex(did.IDStrings[len(did.IDStrings)-1]) {
		return nil, xerrors.Errorf("%s is not 32 byte hex string", did.IDStrings[len(did.IDStrings)-1])
	}
	if did.Path != "" || did.Query != "" {
		return nil, xerrors.Errorf("unsupported path and query in memo did")
	}
	if !isSupport(did.Fragment) && (len(did.Fragment) <= 4 || did.Fragment[:4] != "key-" || isNotPositiveNumber(did.Fragment[4:])) {
		return nil, xerrors.Errorf("unsupportted fragment: %s", did.Fragment)
	}
	return &MemoDIDUrl{
		Method:      did.Method,
		Identifier:  did.ID,
		Identidiers: did.IDStrings,
		Fragment:    did.Fragment,
	}, nil
}

func (d *MemoDIDUrl) String() string {
	return "did:" + d.Method + ":" + d.Identifier + "#" + d.Fragment
}

func (d MemoDIDUrl) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *MemoDIDUrl) UnmarshalJSON(data []byte) error {
	var didUrlString string
	err := json.Unmarshal(data, &didUrlString)
	if err != nil {
		return err
	}
	didUrl, err := ParseMemoDIDUrl(didUrlString)
	if err != nil {
		return err
	}
	d.Method = didUrl.Method
	d.Identifier = didUrl.Identifier
	d.Identidiers = didUrl.Identidiers
	d.Fragment = didUrl.Fragment
	return nil
}

func (d *MemoDIDUrl) GetMethodIndex() int {
	if d.Fragment == "masterKey" {
		return 0
	}
	if d.Fragment[:4] == "key-" {
		if i, err := strconv.Atoi(d.Fragment[4:]); err == nil {
			return i
		}
	}
	return -1
}

func (d *MemoDIDUrl) DID() MemoDID {
	return MemoDID{
		Method:      d.Method,
		Identifier:  d.Identifier,
		Identifiers: d.Identidiers,
	}
}

func isSupport(fragment string) bool {
	for _, frag := range supportFrangment {
		if frag == fragment {
			return true
		}
	}
	return false
}

func isNot32ByteHex(s string) bool {
	if len(s) != 64 {
		return true
	}

	for _, b := range s {
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')) {
			return true
		}
	}

	return false
}

func isNotPositiveNumber(s string) bool {
	if s == "" || s == "0" {
		return true
	}

	for _, b := range s {
		if b < '0' || b > '9' {
			return true
		}
	}

	return false
}
