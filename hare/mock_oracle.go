package hare

import (
	"encoding/binary"
	"github.com/spacemeshos/go-spacemesh/crypto"
	"sync"
)

type Role byte

const (
	Passive = Role(0)
	Active  = Role(1)
	Leader  = Role(2)
)

type Rolacle interface {
	Role(r uint32, sig Signature) Role
}

type MockHashOracle struct {
	clients       map[string]struct{}
	comitySize    int
}

// N is the expected comity size
func NewMockOracle(expectedSize int, comitySize int) *MockHashOracle {
	mock := new(MockHashOracle)
	mock.clients = make(map[string]struct{}, expectedSize)
	mock.comitySize = comitySize

	return mock
}

func (mock *MockHashOracle) Register(pubKey crypto.PublicKey) {
	if _, exist := mock.clients[pubKey.String()]; exist {
		return
	}

	mock.clients[pubKey.String()] = struct{}{}
}

func (mock *MockHashOracle) Unregister(pubKey crypto.PublicKey) {
	delete(mock.clients, pubKey.String())
}

func (mock *MockHashOracle) Role(k uint32, proof Signature) Role {
	if proof == nil {
		return Passive
	}

	population := len(mock.clients)
	singleProbability := mock.comitySize / population
	threshLeader := 1 * singleProbability
	threshActive := 2

	data := binary.LittleEndian.Uint32(proof)

	if data < threshLeader {
		return Leader
	}

	if data < threshActive {
		return Active
	}

	return Passive
}

type MockStaticOracle struct {
	roles       map[uint32]Role
	r           uint32
	defaultSize int
	hasLeader   bool
	mutex       sync.Mutex
}

func NewMockStaticOracle(defaultSize int) *MockStaticOracle {
	static := &MockStaticOracle{}
	static.roles = make(map[uint32]Role, defaultSize)
	static.defaultSize = defaultSize
	static.hasLeader = false

	return static
}

func (static *MockStaticOracle) Role(r uint32, proof Signature) Role {
	return roleFromRoundCounter(r)
}
