// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package inihash implements the inihash proof-of-work consensus engine.
package inihash

import (
	"errors"
	"math/big"
	"math/rand"
	"sync"
	"time"
	"unsafe"

	"PureChain/consensus"
	"PureChain/log"
	"PureChain/metrics"
	"PureChain/rpc"
	"github.com/hashicorp/golang-lru/simplelru"
)

var ErrInvalidDumpMagic = errors.New("invalid dump magic")

var (
	// two256 is a big integer representing 2^256
	two256 = new(big.Int).Exp(big.NewInt(2), big.NewInt(256), big.NewInt(0))

	// sharedEthash is a full instance that can be shared between multiple users.
	sharedEthash *Inihash

	// algorithmRevision is the data structure version used for file naming.
	algorithmRevision = 1

	// dumpMagic is a dataset dump header to sanity check a data dump.
	dumpMagic = []uint32{0xbaddcafe, 0xfee1dead}
)

func init() {
	sharedConfig := Config{
		PowMode:       ModeNormal,
		CachesInMem:   3,
		DatasetsInMem: 1,
	}
	sharedEthash = New(sharedConfig, nil, false)
}

// isLittleEndian returns whether the local system is running in little or big
// endian byte order.
func isLittleEndian() bool {
	n := uint32(0x01020304)
	return *(*byte)(unsafe.Pointer(&n)) == 0x04
}

// lru tracks caches or datasets by their last use time, keeping at most N of them.
type lru struct {
	what string
	new  func(epoch uint64) interface{}
	mu   sync.Mutex
	// Items are kept in a LRU cache, but there is a special case:
	// We always keep an item for (highest seen epoch) + 1 as the 'future item'.
	cache      *simplelru.LRU
	future     uint64
	futureItem interface{}
}

// newlru create a new least-recently-used cache for either the verification caches
// or the mining datasets.
func newlru(what string, maxItems int, new func(epoch uint64) interface{}) *lru {
	if maxItems <= 0 {
		maxItems = 1
	}
	cache, _ := simplelru.NewLRU(maxItems, func(key, value interface{}) {
		log.Trace("Evicted inihash "+what, "epoch", key)
	})
	return &lru{what: what, new: new, cache: cache}
}

// get retrieves or creates an item for the given epoch. The first return value is always
// non-nil. The second return value is non-nil if lru thinks that an item will be useful in
// the near future.
func (lru *lru) get(epoch uint64) (item, future interface{}) {
	lru.mu.Lock()
	defer lru.mu.Unlock()

	// Get or create the item for the requested epoch.
	item, ok := lru.cache.Get(epoch)
	if !ok {
		if lru.future > 0 && lru.future == epoch {
			item = lru.futureItem
		} else {
			log.Trace("Requiring new inihash "+lru.what, "epoch", epoch)
			item = lru.new(epoch)
		}
		lru.cache.Add(epoch, item)
	}
	// Update the 'future item' if epoch is larger than previously seen.
	if epoch < maxEpoch-1 && lru.future < epoch+1 {
		log.Trace("Requiring new future inihash "+lru.what, "epoch", epoch+1)
		future = lru.new(epoch + 1)
		lru.future = epoch + 1
		lru.futureItem = future
	}
	return item, future
}

// Mode defines the type and amount of PoW verification an inihash engine makes.
type Mode uint

const (
	ModeNormal Mode = iota
	ModeShared
	ModeTest
	ModeFake
	ModeFullFake
)

// Config are the configuration parameters of the inihash.
type Config struct {
	CacheDir         string
	CachesInMem      int
	CachesOnDisk     int
	CachesLockMmap   bool
	DatasetDir       string
	DatasetsInMem    int
	DatasetsOnDisk   int
	DatasetsLockMmap bool
	PowMode          Mode

	// When set, notifications sent by the remote sealer will
	// be block header JSON objects instead of work package arrays.
	NotifyFull bool

	Log log.Logger `toml:"-"`
}

// Inihash is a consensus engine based on proof-of-work implementing the inihash
// algorithm.
type Inihash struct {
	config Config

	// Mining related fields
	rand     *rand.Rand    // Properly seeded random source for nonces
	threads  int           // Number of threads to mine on if mining
	update   chan struct{} // Notification channel to update mining parameters
	hashrate metrics.Meter // Meter tracking the average hashrate
	remote   *remoteSealer

	// The fields below are hooks for testing
	shared    *Inihash      // Shared PoW verifier to avoid cache regeneration
	fakeFail  uint64        // Block number which fails PoW check even in fake mode
	fakeDelay time.Duration // Time delay to sleep for before returning from verify

	lock      sync.Mutex // Ensures thread safety for the in-memory caches and mining fields
	closeOnce sync.Once  // Ensures exit channel will not be closed twice.
}

// New creates a full sized inihash PoW scheme and starts a background thread for
// remote mining, also optionally notifying a batch of remote services of new work
// packages.
func New(config Config, notify []string, noverify bool) *Inihash {
	if config.Log == nil {
		config.Log = log.Root()
	}
	//if config.CachesInMem <= 0 {
	//	config.Log.Warn("One inihash cache must always be in memory", "requested", config.CachesInMem)
	//	config.CachesInMem = 1
	//}
	//if config.CacheDir != "" && config.CachesOnDisk > 0 {
	//	config.Log.Info("Disk storage enabled for inihash caches", "dir", config.CacheDir, "count", config.CachesOnDisk)
	//}
	//if config.DatasetDir != "" && config.DatasetsOnDisk > 0 {
	//	config.Log.Info("Disk storage enabled for inihash DAGs", "dir", config.DatasetDir, "count", config.DatasetsOnDisk)
	//}
	ethash := &Inihash{
		config:   config,
		update:   make(chan struct{}),
		hashrate: metrics.NewMeterForced(),
	}
	if config.PowMode == ModeShared {
		ethash.shared = sharedEthash
	}
	ethash.remote = startRemoteSealer(ethash, notify, noverify)
	return ethash
}

// NewTester creates a small sized inihash PoW scheme useful only for testing
// purposes.
func NewTester(notify []string, noverify bool) *Inihash {
	return New(Config{PowMode: ModeTest}, notify, noverify)
}

// NewFaker creates a inihash consensus engine with a fake PoW scheme that accepts
// all blocks' seal as valid, though they still have to conform to the Ethereum
// consensus rules.
func NewFaker() *Inihash {
	return &Inihash{
		config: Config{
			PowMode: ModeFake,
			Log:     log.Root(),
		},
	}
}

// NewFakeFailer creates a inihash consensus engine with a fake PoW scheme that
// accepts all blocks as valid apart from the single one specified, though they
// still have to conform to the Ethereum consensus rules.
func NewFakeFailer(fail uint64) *Inihash {
	return &Inihash{
		config: Config{
			PowMode: ModeFake,
			Log:     log.Root(),
		},
		fakeFail: fail,
	}
}

// NewFakeDelayer creates a inihash consensus engine with a fake PoW scheme that
// accepts all blocks as valid, but delays verifications by some time, though
// they still have to conform to the Ethereum consensus rules.
func NewFakeDelayer(delay time.Duration) *Inihash {
	return &Inihash{
		config: Config{
			PowMode: ModeFake,
			Log:     log.Root(),
		},
		fakeDelay: delay,
	}
}

// NewFullFaker creates an inihash consensus engine with a full fake scheme that
// accepts all blocks as valid, without checking any consensus rules whatsoever.
func NewFullFaker() *Inihash {
	return &Inihash{
		config: Config{
			PowMode: ModeFullFake,
			Log:     log.Root(),
		},
	}
}

// NewShared creates a full sized inihash PoW shared between all requesters running
// in the same process.
func NewShared() *Inihash {
	return &Inihash{shared: sharedEthash}
}

// Close closes the exit channel to notify all backend threads exiting.
func (inihash *Inihash) Close() error {
	inihash.closeOnce.Do(func() {
		// Short circuit if the exit channel is not allocated.
		if inihash.remote == nil {
			return
		}
		close(inihash.remote.requestExit)
		<-inihash.remote.exitCh
	})
	return nil
}

// Threads returns the number of mining threads currently enabled. This doesn't
// necessarily mean that mining is running!
func (inihash *Inihash) Threads() int {
	inihash.lock.Lock()
	defer inihash.lock.Unlock()

	return inihash.threads
}

// SetThreads updates the number of mining threads currently enabled. Calling
// this method does not start mining, only sets the thread count. If zero is
// specified, the miner will use all cores of the machine. Setting a thread
// count below zero is allowed and will cause the miner to idle, without any
// work being done.
func (inihash *Inihash) SetThreads(threads int) {
	inihash.lock.Lock()
	defer inihash.lock.Unlock()

	// If we're running a shared PoW, set the thread count on that instead
	if inihash.shared != nil {
		inihash.shared.SetThreads(threads)
		return
	}
	// Update the threads and ping any running seal to pull in any changes
	inihash.threads = threads
	select {
	case inihash.update <- struct{}{}:
	default:
	}
}

// Hashrate implements PoW, returning the measured rate of the search invocations
// per second over the last minute.
// Note the returned hashrate includes local hashrate, but also includes the total
// hashrate of all remote miner.
func (inihash *Inihash) Hashrate() float64 {
	// Short circuit if we are run the inihash in normal/test mode.
	if inihash.config.PowMode != ModeNormal && inihash.config.PowMode != ModeTest {
		return inihash.hashrate.Rate1()
	}
	var res = make(chan uint64, 1)

	select {
	case inihash.remote.fetchRateCh <- res:
	case <-inihash.remote.exitCh:
		// Return local hashrate only if inihash is stopped.
		return inihash.hashrate.Rate1()
	}

	// Gather total submitted hash rate of remote sealers.
	return inihash.hashrate.Rate1() + float64(<-res)
}

func (Inihash *Inihash) GetBlockReward(blockHeight uint64) *big.Int {
	return CalBlockReward(blockHeight)
}

// APIs implements consensus.Engine, returning the user facing RPC APIs.
func (inihash *Inihash) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	// In order to ensure backward compatibility, we exposes inihash RPC APIs
	// to both eth and inihash namespaces.
	return []rpc.API{
		{
			Namespace: "eth",
			Version:   "1.0",
			Service:   &API{inihash},
			Public:    true,
		},
		{
			Namespace: "inihash",
			Version:   "1.0",
			Service:   &API{inihash},
			Public:    true,
		},
	}
}

// SeedHash is the seed to use for generating a verification cache and the mining
// dataset.
func SeedHash(block uint64) []byte {
	return seedHash(block)
}
