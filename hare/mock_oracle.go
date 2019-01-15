package hare

import (
	"encoding/binary"
	"github.com/spacemeshos/go-spacemesh/crypto"
	"github.com/spacemeshos/go-spacemesh/log"
	"math"
	"sync"
)

type Role byte

const (
	Passive = Role(0)
	Active  = Role(1)
	Leader  = Role(2)
)

type Rolacle interface {
	Role(sig Signature) Role
}

type MockHashOracle struct {
	clients    map[string]struct{}
	comitySize int
	mutex      sync.Mutex
}

// N is the expected comity size
func NewMockHashOracle(expectedSize int, comitySize int) *MockHashOracle {
	mock := new(MockHashOracle)
	mock.clients = make(map[string]struct{}, expectedSize)
	mock.comitySize = comitySize

	return mock
}

func (mock *MockHashOracle) Register(pubKey crypto.PublicKey) {
	mock.mutex.Lock()
	defer mock.mutex.Unlock()

	if _, exist := mock.clients[pubKey.String()]; exist {
		return
	}

	mock.clients[pubKey.String()] = struct{}{}
}

func (mock *MockHashOracle) Unregister(pubKey crypto.PublicKey) {
	mock.mutex.Lock()
	delete(mock.clients, pubKey.String())
	mock.mutex.Unlock()
}

func (mock *MockHashOracle) Role(proof Signature) Role {
	if proof == nil {
		log.Warning("Oracle query with proof=nil. Returning passive")
		return Passive
	}

	population := float32(len(mock.clients))
	threshLeader := uint32(float32(5) / population * math.MaxUint32)               // expect 5 leaders
	threshActive := uint32(float32(mock.comitySize) / population * math.MaxUint32) // expect comitySize actives

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
