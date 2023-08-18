package dpos

import (
	"PureChain"
	"PureChain/metrics"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/crypto/sha3"

	_ "PureChain"
	"PureChain/accounts"
	"PureChain/accounts/abi"
	"PureChain/common"
	"PureChain/common/gopool"
	"PureChain/common/hexutil"
	"PureChain/consensus"
	"PureChain/consensus/dpos/systemcontract"
	"PureChain/consensus/dpos/vmcaller"
	"PureChain/consensus/misc"
	"PureChain/core"
	"PureChain/core/forkid"
	"PureChain/core/state"
	"PureChain/core/systemcontracts"
	"PureChain/core/types"
	"PureChain/core/vm"
	"PureChain/crypto"
	"PureChain/ethdb"
	"PureChain/internal/ethapi"
	"PureChain/log"
	"PureChain/params"
	"PureChain/rlp"
	"PureChain/rpc"
	"PureChain/trie"
)

const (
	inMemorySnapshots  = 128  // Number of recent snapshots to keep in memory
	inMemorySignatures = 4096 // Number of recent block signatures to keep in memory

	checkpointInterval     = 1024                     // Number of blocks after which to save the snapshot to the database
	defaultEpochLength     = uint64(100)              // Default number of blocks of checkpoint to update validatorSet from contract
	defaultPorChallengeUrl = "http://127.0.0.1:18077" // Default por challenge commit url
	maxValidators          = 21                       // Max validators allowed to seal.
	extraVanity            = 32                       // Fixed number of extra-data prefix bytes reserved for signer vanity
	extraSeal              = 65                       // Fixed number of extra-data suffix bytes reserved for signer seal
	nextForkHashSize       = 4                        // Fixed number of extra-data suffix bytes reserved for nextForkHash.

	validatorBytesLength = common.AddressLength
	wiggleTime           = uint64(1) // second, Random delay (per signer) to allow concurrent signers
	initialBackOffTime   = uint64(1) // second

	systemRewardPercent   = 4           // it means 1/2^4 = 1/16 percentage of gas fee incoming will be distributed to system
	inmemoryBlacklist     = 21          // Number of recent blacklist snapshots to keep in memory
	allPercent            = 10000       // Number of all distribute percent
	doubleAllPercent      = 20000       // Number of all distribute percent
	distributeRound       = 100         // Number of distribute round
	doubleDistributeRound = 200         // Double Number of distribute round
	blockDistributeRewrad = 61969993482 // one block origin reward
	//todo change year blockCount for mainnet
	yearBlockCount = 24 * 60 * 10 // one year generate block count
	oneTDiv1000    = 1073741824   // 1024*1024*1024*1024/1000
	oneGDiv1000    = 1048576      // 1024*1024*1024/1000
	//todo change rate for mainnet
	challengeRate           = 30000           // One in 10,000  chance of triggering a challenge
	maxSeedInt              = int64(1) << 62  // maxSeedInt
	defaultGasLimit         = uint64(1000000) // default 100w gas limit
	defaultGasPrice         = int64(100)      // default 100 gas price
	challengeInterval       = 4 * time.Hour   // default challenge interval
	punishChallengeInterval = 2 * time.Hour   // default punish provider challenge interval
)

const (
	Running uint8 = iota
	Punish
	Pause
	Stop
)

const (
	NotStart uint8 = iota
	Create
	Success
	Fail
)

var (
	fourGMem                = big.NewInt(4 * 1024 * 1024 * 1024) // 4G memory
	challengeProviderMethod = crypto.Keccak256Hash([]byte("challengeProvider(address,uint256,string)")).String()[2:10]
	challengeFinishMethod   = crypto.Keccak256Hash([]byte("challengeFinish(address,uint256,uint256,uint256,uint8)")).String()[2:10]
	challengeRevertMethod   = crypto.Keccak256Hash([]byte("validatorNotSubmitResult(address)")).String()[2:10]
)

type blacklistDirection uint

const (
	DirectionFrom blacklistDirection = iota
	DirectionTo
	DirectionBoth
)

var (
	uncleHash  = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.
	diffInTurn = big.NewInt(2)            // Block difficulty for in-turn signatures
	diffNoTurn = big.NewInt(1)            // Block difficulty for out-of-turn signatures
	// 100 native token
	maxSystemBalance = new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether))
	//ProviderFactoryAddr = common.Address{}
	StakeThreshold  = new(big.Int).Mul(big.NewInt(1000), big.NewInt(params.Ether))
	LuckyRate       = big.NewInt(6)
	LuckyPorRate    = big.NewInt(4)
	MaxStorage      = big.NewInt(1)
	MaxMemory       = big.NewInt(4)
	systemContracts = map[common.Address]bool{
		systemcontract.ValidatorFactoryContractAddr: true,
		systemcontract.ProviderFactoryContractAddr:  true,
		/*
			systemcontract.DposFactoryContractAddr: true,
			systemcontract.AddressListContractAddr: true,
			systemcontract.PunishV1ContractAddr:    true,
			systemcontract.SysGovContractAddr:      true,
		*/
	}
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	// errUnknownBlock is returned when the list of validators is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errMissingVanity is returned if a block's extra-data section is shorter than
	// 32 bytes, which is required to store the signer vanity.
	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")

	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte signature suffix missing")

	// errExtraValidators is returned if non-sprint-end block contain validator data in
	// their extra-data fields.
	errExtraValidators = errors.New("non-sprint-end block contains extra validator list")

	// errInvalidSpanValidators is returned if a block contains an
	// invalid list of validators (i.e. non divisible by 20 bytes).
	errInvalidSpanValidators       = errors.New("invalid validator list on sprint end block")
	errInvalidCheckpointValidators = errors.New("invalid validator list on checkpoint block")

	// errMismatchingCheckpointValidators is returned if a checkpoint block contains a
	// list of validators different than the one the local node calculated.
	errMismatchingCheckpointValidators = errors.New("mismatching validator list on checkpoint block")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errInvalidProvider is returned if a block calculate illegal provider.
	errInvalidProvider = errors.New("illegal provider")
	// errInvalidTeamAddress is returned if a block calculate illegal teamAddress.
	errInvalidTeamAddr = errors.New("illegal team address")

	// errInvalidDistributeRate is returned if a block set illegal distribute rate.
	errInvalidDistributeRate = errors.New("illegal distribute rate")

	// errMismatchingEpochValidators is returned if a sprint block contains a
	// list of validators different than the one the local node calculated.
	errMismatchingEpochValidators = errors.New("mismatching validator list on epoch block")

	// errInvalidDifficulty is returned if the difficulty of a block is missing.
	errInvalidDifficulty = errors.New("invalid difficulty")

	// errWrongDifficulty is returned if the difficulty of a block doesn't match the
	// turn of the signer.
	errWrongDifficulty = errors.New("wrong difficulty")

	// errOutOfRangeChain is returned if an authorization list is attempted to
	// be modified via out-of-range or non-contiguous headers.
	errOutOfRangeChain = errors.New("out of range or non-contiguous chain")
	// errInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	errInvalidTimestamp = errors.New("invalid timestamp")

	// ErrInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	ErrInvalidTimestamp = errors.New("invalid timestamp")
	// errInvalidVotingChain is returned if an authorization list is attempted to
	// be modified via out-of-range or non-contiguous headers.
	errInvalidVotingChain = errors.New("invalid voting chain")

	// errBlockHashInconsistent is returned if an authorization list is attempted to
	// insert an inconsistent block.
	errBlockHashInconsistent = errors.New("the block hash is inconsistent")

	// errUnauthorizedValidator is returned if a header is signed by a non-authorized entity.
	errUnauthorizedValidator = errors.New("unauthorized validator")

	// errCoinBaseMisMatch is returned if a header's coinbase do not match with signature
	errCoinBaseMisMatch = errors.New("coinbase do not match with signature")

	// errRecentlySigned is returned if a header is signed by an authorized entity
	// that already signed a header recently, thus is temporarily not allowed to.
	errRecentlySigned = errors.New("recently signed")

	// errInvalidValidatorLen is returned if validators length is zero or bigger than maxValidators.
	errInvalidValidatorsLength = errors.New("Invalid validators length")

	// errInvalidCoinbase is returned if the coinbase isn't the validator of the block.
	errInvalidCoinbase = errors.New("Invalid coin base")

	errInvalidSysGovCount = errors.New("invalid system governance tx count")
)

var (
	getblacklistTimer = metrics.NewRegisteredTimer("dpos/blacklist/get", nil)
)

// SignerFn is a signer callback function to request a header to be signed by a
// backing account.
type StateFn func(hash common.Hash) (*state.StateDB, error)

type SignerFn func(accounts.Account, string, []byte) ([]byte, error)
type SignerTxFn func(accounts.Account, *types.Transaction, *big.Int) (*types.Transaction, error)

type VoteInfo struct {
	ProviderAddress common.Address `json:"provider_address"`
	VotingPower     *big.Int       `json:"voting_power"`
}
type ProviderInfos struct {
	ProviderContract common.Address
	Info             providerInfo
	MarginAmount     *big.Int
	Audits           []common.Address
}

type providerChallengeInfo struct {
	Provider            common.Address `json:"provider"`
	ChallengeValidator  common.Address `json:"challenge_validator"`
	Md5Seed             *big.Int       `json:"md5_seed"`
	Url                 string         `json:"url"`
	CreateChallengeTime *big.Int       `json:"create_challenge_time"`
	ChallengeFinishTime *big.Int       `json:"challenge_finish_time"`
	State               uint8          `json:"state"`
	ChallengeAmount     *big.Int       `json:"challenge_amount"`
	Seed                *big.Int       `json:"seed"`
	RootHash            *big.Int       `json:"root_hash"`
	Index               *big.Int       `json:"seed"`
}

// poaResource is an auto generated low-level Go binding around an user-defined struct.
type poaResource struct {
	CpuCount     *big.Int
	MemoryCount  *big.Int
	StorageCount *big.Int
}

// providerInfo is an auto generated low-level Go binding around an user-defined struct.
type providerInfo struct {
	Total             poaResource
	Used              poaResource
	Lock              poaResource
	Challenge         bool
	State             uint8
	Owner             common.Address
	Region            string
	Info              string
	LastChallengeTime *big.Int
	LastMarginTime    *big.Int
}

func isToSystemContract(to common.Address) bool {
	return systemContracts[to]
}

// ecrecover extracts the Ethereum account address from a signed header.
func ecrecover(header *types.Header, sigCache *lru.ARCCache, chainId *big.Int) (common.Address, error) {
	// If the signature's already cached, return that
	hash := header.Hash()
	if address, known := sigCache.Get(hash); known {
		return address.(common.Address), nil
	}
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]

	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(SealHash(header, chainId).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	sigCache.Add(hash, signer)
	return signer, nil
}

// DposRLP returns the rlp bytes which needs to be signed for the dpos
// sealing. The RLP to sign consists of the entire header apart from the 65 byte signature
// contained at the end of the extra data.
//
// Note, the method requires the extra data to be at least 65 bytes, otherwise it
// panics. This is done to avoid accidentally using both forms (signature present
// or not), which could be abused to produce different hashes for the same header.
func DposRLP(header *types.Header, chainId *big.Int) []byte {
	b := new(bytes.Buffer)
	encodeSigHeader(b, header, chainId)
	return b.Bytes()
}

// Dpos is the consensus engine of BSC
type Dpos struct {
	chainConfig *params.ChainConfig // Chain config
	config      *params.DposConfig  // Consensus engine configuration parameters for dpos consensus
	genesisHash common.Hash
	db          ethdb.Database // Database to store and retrieve snapshot checkpoints

	recentSnaps *lru.ARCCache // Snapshots for recent block to speed up
	signatures  *lru.ARCCache // Signatures of recent blocks to speed up mining
	blacklists  *lru.ARCCache // Blacklist snapshots for recent blocks to speed up transactions validation
	blLock      sync.Mutex    // Make sure only get blacklist once for each block

	proposals map[common.Address]bool // Current list of proposals we are pushing

	signer types.Signer

	val       common.Address // Ethereum address of the signing key
	signFn    SignerFn       // Signer function to authorize hashes with
	signTxFn  SignerTxFn
	signFns   map[common.Address]SignerFn
	signTxFns map[common.Address]SignerTxFn

	lock            sync.RWMutex       // Protects the signer fields
	abi             map[string]abi.ABI // Interactive with system contracts
	ethAPI          *ethapi.PublicBlockChainAPI
	validatorSetABI abi.ABI
	slashABI        abi.ABI
	stateFn         StateFn // Function to get state by state root
	// The fields below are for testing only
	fakeDiff bool // Skip difficulty verifications
}

// New creates a Dpos consensus engine.
func New(
	chainConfig *params.ChainConfig,
	db ethdb.Database,
	ethAPI *ethapi.PublicBlockChainAPI,
	genesisHash common.Hash,
) *Dpos {
	// get dpos config
	dposConfig := chainConfig.Dpos

	// Set any missing consensus parameters to their defaults
	if dposConfig != nil && dposConfig.Epoch == 0 {
		dposConfig.Epoch = defaultEpochLength
	}
	if chainConfig.Dpos.ChallengeCommitUrl == "" {
		dposConfig.ChallengeCommitUrl = defaultPorChallengeUrl
	} else {
		dposConfig.ChallengeCommitUrl = chainConfig.Dpos.ChallengeCommitUrl
	}
	dposConfig.Por = chainConfig.Dpos.Por

	// Allocate the snapshot caches and create the engine
	recentSnaps, err := lru.NewARC(inMemorySnapshots)
	if err != nil {
		panic(err)
	}
	signatures, err := lru.NewARC(inMemorySignatures)
	if err != nil {
		panic(err)
	}
	blacklists, _ := lru.NewARC(inmemoryBlacklist)
	vABI, err := abi.JSON(strings.NewReader(validatorSetABI))
	if err != nil {
		panic(err)
	}
	sABI, err := abi.JSON(strings.NewReader(slashABI))
	if err != nil {
		panic(err)
	}
	abi := systemcontract.GetInteractiveABI()
	c := &Dpos{
		chainConfig:     chainConfig,
		config:          dposConfig,
		genesisHash:     genesisHash,
		db:              db,
		ethAPI:          ethAPI,
		recentSnaps:     recentSnaps,
		signatures:      signatures,
		validatorSetABI: vABI,
		slashABI:        sABI,
		blacklists:      blacklists,
		proposals:       make(map[common.Address]bool),
		abi:             abi,
		signer:          types.NewEIP155Signer(chainConfig.ChainID),
		signTxFns:       make(map[common.Address]SignerTxFn, 0),
		signFns:         make(map[common.Address]SignerFn, 0),
	}

	return c
}

func (p *Dpos) IsSystemTransaction(tx *types.Transaction, header *types.Header) (bool, error) {
	// deploy a contract
	if tx.To() == nil {
		return false, nil
	}
	sender, err := types.Sender(p.signer, tx)
	if err != nil {
		return false, errors.New("UnAuthorized transaction")
	}

	if sender == header.Coinbase && isToSystemContract(*tx.To()) && tx.GasPrice().Cmp(big.NewInt(0)) == 0 && !strings.HasPrefix(hex.EncodeToString(tx.Data()), challengeProviderMethod) && !strings.HasPrefix(hex.EncodeToString(tx.Data()), challengeFinishMethod) && !strings.HasPrefix(hex.EncodeToString(tx.Data()), challengeRevertMethod) {
		return true, nil
	}
	return false, nil
}

func (p *Dpos) IsSystemContract(to *common.Address) bool {
	if to == nil {
		return false
	}
	return isToSystemContract(*to)
}

// SetStateFn sets the function to get state.
func (p *Dpos) SetStateFn(fn StateFn) {
	p.stateFn = fn
}

// Author implements consensus.Engine, returning the SystemAddress
func (p *Dpos) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (p *Dpos) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	return p.verifyHeader(chain, header, nil)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
func (p *Dpos) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	gopool.Submit(func() {
		for i, header := range headers {
			err := p.verifyHeader(chain, header, headers[:i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	})
	return abort, results
}

// verifyHeader checks whether a header conforms to the consensus rules.The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
func (p *Dpos) verifyHeader(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	if header.Number == nil {
		return errUnknownBlock
	}

	number := header.Number.Uint64()

	// Don't waste time checking blocks from the future
	if header.Time > uint64(time.Now().Unix()) {
		return consensus.ErrFutureBlock
	}
	// Check that the extra-data contains the vanity, validators and signature.
	if len(header.Extra) < extraVanity {
		return errMissingVanity
	}
	if len(header.Extra) < extraVanity+extraSeal {
		return errMissingSignature
	}
	// check extra data
	isEpoch := number%p.config.Epoch == 0

	// Ensure that the extra-data contains a signer list on checkpoint, but none otherwise
	signersBytes := len(header.Extra) - extraVanity - extraSeal
	if !isEpoch && signersBytes != 0 {
		return errExtraValidators
	}

	if isEpoch && signersBytes%validatorBytesLength != 0 {
		return errInvalidSpanValidators
	}

	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}

	// Ensure that the block doesn't contain any uncles which are meaningless in PoA
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}
	// Ensure that the block's difficulty is meaningful (may not be correct at this point)
	if number > 0 {
		if header.Difficulty == nil {
			return errInvalidDifficulty
		}
	}
	// If all checks passed, validate any special fields for hard forks
	if err := misc.VerifyForkHashes(chain.Config(), header, false); err != nil {
		return err
	}
	// All basic checks passed, verify cascading fields
	return p.verifyCascadingFields(chain, header, parents)
}

// verifyCascadingFields verifies all the header fields that are not standalone,
// rather depend on a batch of previous headers. The caller may optionally pass
// in a batch of parents (ascending order) to avoid looking those up from the
// database. This is useful for concurrently verifying a batch of new headers.
func (p *Dpos) verifyCascadingFields(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	// The genesis block is the always valid dead-end
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}

	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}

	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}

	snap, err := p.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}

	err = p.blockTimeVerifyForRamanujanFork(snap, header, parent)
	if err != nil {
		return err
	}

	// Verify that the gas limit is <= 2^63-1
	capacity := uint64(0x7fffffffffffffff)
	if header.GasLimit > capacity {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, capacity)
	}
	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}

	// Verify that the gas limit remains within allowed bounds
	diff := int64(parent.GasLimit) - int64(header.GasLimit)
	if diff < 0 {
		diff *= -1
	}
	limit := parent.GasLimit / params.GasLimitBoundDivisor

	if uint64(diff) >= limit || header.GasLimit < params.MinGasLimit {
		return fmt.Errorf("invalid gas limit: have %d, want %d += %d", header.GasLimit, parent.GasLimit, limit)
	}

	// All basic checks passed, verify the seal and return
	return p.verifySeal(chain, header, parents)
}

// snapshot retrieves the authorization snapshot at a given point in time.
func (p *Dpos) snapshot(chain consensus.ChainHeaderReader, number uint64, hash common.Hash, parents []*types.Header) (*Snapshot, error) {
	// Search for a snapshot in memory or on disk for checkpoints
	var (
		headers []*types.Header
		snap    *Snapshot
	)

	for snap == nil {
		// If an in-memory snapshot was found, use that
		if s, ok := p.recentSnaps.Get(hash); ok {
			snap = s.(*Snapshot)
			break
		}

		// If an on-disk checkpoint snapshot can be found, use that
		if number%checkpointInterval == 0 {
			if s, err := loadSnapshot(p.config, p.signatures, p.db, hash, p.ethAPI); err == nil {
				log.Trace("Loaded snapshot from disk", "number", number, "hash", hash)
				snap = s
				break
			}
		}

		// If we're at the genesis, snapshot the initial state.
		if number == 0 {
			checkpoint := chain.GetHeaderByNumber(number)
			if checkpoint != nil {
				// get checkpoint data
				hash := checkpoint.Hash()

				validatorBytes := checkpoint.Extra[extraVanity : len(checkpoint.Extra)-extraSeal]
				// get validators from headers
				validators, err := ParseValidators(validatorBytes)
				if err != nil {
					return nil, err
				}

				// new snap shot
				snap = newSnapshot(p.config, p.signatures, number, hash, validators, p.ethAPI)
				if err := snap.store(p.db); err != nil {
					return nil, err
				}
				log.Info("Stored checkpoint snapshot to disk", "number", number, "hash", hash)
				break
			}
		}

		// No snapshot for this header, gather the header and move backward
		var header *types.Header
		if len(parents) > 0 {
			// If we have explicit parents, pick from there (enforced)
			header = parents[len(parents)-1]
			if header.Hash() != hash || header.Number.Uint64() != number {
				return nil, consensus.ErrUnknownAncestor
			}
			parents = parents[:len(parents)-1]
		} else {
			// No explicit parents (or no more left), reach out to the database
			header = chain.GetHeader(hash, number)
			if header == nil {
				return nil, consensus.ErrUnknownAncestor
			}
		}
		headers = append(headers, header)
		number, hash = number-1, header.ParentHash
	}

	// check if snapshot is nil
	if snap == nil {
		return nil, fmt.Errorf("unknown error while retrieving snapshot at block number %v", number)
	}

	// Previous snapshot found, apply any pending headers on top of it
	for i := 0; i < len(headers)/2; i++ {
		headers[i], headers[len(headers)-1-i] = headers[len(headers)-1-i], headers[i]
	}

	snap, err := snap.apply(headers, chain, parents, p.chainConfig.ChainID)
	if err != nil {
		return nil, err
	}
	p.recentSnaps.Add(snap.Hash, snap)

	// If we've generated a new checkpoint snapshot, save to disk
	if snap.Number%checkpointInterval == 0 && len(headers) > 0 {
		if err = snap.store(p.db); err != nil {
			return nil, err
		}
		log.Trace("Stored snapshot to disk", "number", snap.Number, "hash", snap.Hash)
	}
	return snap, err
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (p *Dpos) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// VerifySeal implements consensus.Engine, checking whether the signature contained
// in the header satisfies the consensus protocol requirements.
func (p *Dpos) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	return p.verifySeal(chain, header, nil)
}

// verifySeal checks whether the signature contained in the header satisfies the
// consensus protocol requirements. The method accepts an optional list of parent
// headers that aren't yet part of the local blockchain to generate the snapshots
// from.
func (p *Dpos) verifySeal(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	// Verifying the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}
	// Retrieve the snapshot needed to verify this header and cache it
	snap, err := p.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}

	// Resolve the authorization key and check against validators
	signer, err := ecrecover(header, p.signatures, p.chainConfig.ChainID)
	if err != nil {
		return err
	}

	if signer != header.Coinbase {
		return errCoinBaseMisMatch
	}

	if _, ok := snap.Validators[signer]; !ok {
		return errUnauthorizedValidator
	}

	for seen, recent := range snap.Recents {
		if recent == signer {
			// Signer is among recents, only fail if the current block doesn't shift it out
			if limit := uint64(len(snap.Validators)/2 + 1); seen > number-limit {
				return errRecentlySigned
			}
		}
	}

	// Ensure that the difficulty corresponds to the turn-ness of the signer
	if !p.fakeDiff {
		inturn := snap.inturn(signer)
		if inturn && header.Difficulty.Cmp(diffInTurn) != 0 {
			return errWrongDifficulty
		}
		if !inturn && header.Difficulty.Cmp(diffNoTurn) != 0 {
			return errWrongDifficulty
		}
	}

	return nil
}

func (p *Dpos) CheckHasInTurn(chain consensus.ChainHeaderReader, coinbases []common.Address, header *types.Header) common.Address {
	number := header.Number.Uint64()
	snap, err := p.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return common.Address{}

	}
	for _, coinbase := range coinbases {

		difficulty := CalcDifficulty(snap, coinbase)
		if difficulty.Cmp(diffInTurn) == 0 {
			log.Info("find in turn account")
			return coinbase
		}
	}
	log.Info("not find in turn account")
	return common.Address{}
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (p *Dpos) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	//fmt.Println("prepare1")
	header.Coinbase = p.val
	//log.Info(header.Coinbase.String())
	header.Nonce = types.BlockNonce{}

	number := header.Number.Uint64()
	snap, err := p.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	//TODO: 获取质押合约的参数
	providerDetailData, err := p.getProviderInfo(chain, header)
	if err != nil {
		log.Error("getProviderInfo error", "error", err)
	}

	realTeamRate, realValRate := p.getDistributeRate(chain, header)
	totalVote := big.NewInt(0)
	for _, k := range providerDetailData {
		totalVote.Add(totalVote, k.VotingPower)
	}
	if totalVote.Cmp(common.Big0) > 0 {
		parentHeader := chain.GetHeaderByHash(header.ParentHash)
		if parentHeader != nil {
			calRlp, err := rlp.EncodeToBytes([]interface{}{parentHeader.Root, header.ParentHash, parentHeader.Coinbase, parentHeader.Time})
			if err != nil {
				return err
			}

			calHash := crypto.Keccak256(calRlp)
			magicNumber := big.NewInt(0).SetBytes(calHash)
			magicNumber.Mod(magicNumber, totalVote)
			currentVote := big.NewInt(0)

			for _, v := range providerDetailData {
				currentVote.Add(currentVote, v.VotingPower)
				if magicNumber.Cmp(currentVote) < 0 {
					header.Provider = v.ProviderAddress
					log.Info("Choose provider", "provider", v.ProviderAddress, "votepower", v.VotingPower, "currentVote", currentVote)
					break
				}
			}
		} else {

			header.Provider = common.Address{}
		}
	} else {
		header.Provider = common.Address{}

	}
	header.TeamRate = realTeamRate
	header.ValidatorRate = realValRate
	header.TeamAddress, _ = p.getTeamAddress(chain, header)

	// Set the correct difficulty
	header.Difficulty = CalcDifficulty(snap, p.val)

	// Ensure the extra data has all it's components
	if len(header.Extra) < extraVanity-nextForkHashSize {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, extraVanity-nextForkHashSize-len(header.Extra))...)
	}
	header.Extra = header.Extra[:extraVanity-nextForkHashSize]
	nextForkHash := forkid.NextForkHash(p.chainConfig, p.genesisHash, number)
	header.Extra = append(header.Extra, nextForkHash[:]...)

	if number%p.config.Epoch == 0 {
		newValidators, err := p.getTopValidators(chain, header)
		if err != nil {
			return err
		}
		// sort validator by address
		sort.Sort(validatorsAscending(newValidators))
		for _, validator := range newValidators {
			header.Extra = append(header.Extra, validator.Bytes()...)
		}
	}

	// add extra seal space
	header.Extra = append(header.Extra, make([]byte, extraSeal)...)

	// Mix digest is reserved for now, set to empty
	header.MixDigest = common.Hash{}

	// Ensure the timestamp has the correct delay
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Time = p.blockTimeForRamanujanFork(snap, header, parent)
	if header.Time < uint64(time.Now().Unix()) {
		header.Time = uint64(time.Now().Unix())
	}

	return nil
}

// Finalize implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given.
func (p *Dpos) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs *[]*types.Transaction,
	uncles []*types.Header, receipts *[]*types.Receipt, systemTxs *[]*types.Transaction, usedGas *uint64) error {
	// Initialize all system contracts at block 1.
	if header.Number.Cmp(common.Big1) == 0 {
		if err := p.initializeSystemContracts(chain, header, state); err != nil {
			log.Error("Initialize system contracts failed", "err", err)
			return err
		}
	}
	if err := p.tryPunishValidator(chain, header, state); err != nil {
		return err
	}
	if err := p.punishProvider(chain, header, state); err != nil {
		return err
	}
	/*
		if header.Difficulty.Cmp(diffInTurn) != 0 {
			if err := p.tryPunishValidator(chain, header, state); err != nil {
				return err
			}
		}*/
	// avoid nil pointer
	if txs == nil {
		s := make([]*types.Transaction, 0)
		txs = &s
	}
	if receipts == nil {
		rs := make([]*types.Receipt, 0)
		receipts = &rs
	}

	// execute block reward tx.
	//if len(*txs) > 0 {
	if header.Number.Cmp(common.Big3) > 0 {
		if err := p.trySendBlockReward(chain, header, state); err != nil {
			return err
		}
	}

	//}

	// warn if not in majority fork
	number := header.Number.Uint64()
	snap, err := p.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	nextForkHash := forkid.NextForkHash(p.chainConfig, p.genesisHash, number)
	if !snap.isMajorityFork(hex.EncodeToString(nextForkHash[:])) {
		log.Debug("there is a possible fork, and your client is not the majority. Please check...", "nextForkHash", hex.EncodeToString(nextForkHash[:]))
	}
	// If the block is a epoch end block, verify the validator list
	// The verification can only be done when the state is ready, it can't be done in VerifyHeader.
	if header.Number.Uint64()%p.config.Epoch == 0 {

		newValidators, err := p.doSomethingAtEpoch(chain, header, state)
		if err != nil {
			return err
		}

		validatorsBytes := make([]byte, len(newValidators)*common.AddressLength)

		//newValidators, err := p.getCurrentValidators(header.ParentHash)
		//if err != nil {
		//	return err
		//}
		// sort validator by address
		//sort.Sort(validatorsAscending(newValidators))
		//validatorsBytes := make([]byte, len(newValidators)*validatorBytesLength)
		for i, validator := range newValidators {
			copy(validatorsBytes[i*validatorBytesLength:], validator.Bytes())
		}

		extraSuffix := len(header.Extra) - extraSeal
		if !bytes.Equal(header.Extra[extraVanity:extraSuffix], validatorsBytes) {
			return errMismatchingEpochValidators
		}
	}
	// No block rewards in PoA, so the state remains as is and uncles are dropped
	//cx := chainContext{Chain: chain, dpos: p}
	//if header.Number.Cmp(common.Big1) == 0 {
	//	err := p.initContract(state, header, cx, txs, receipts, systemTxs, usedGas, false)
	//	if err != nil {
	//		log.Error("init contract failed")
	//	}
	//}

	//handle system governance Proposal
	if chain.Config().IsRedCoast(header.Number) {
		proposalCount, err := p.getPassedProposalCount(chain, header, state)
		if err != nil {
			return err
		}
		if proposalCount != uint32(len(*systemTxs)) {
			return errInvalidSysGovCount
		}
		// Due to the logics of the finish operation of contract `governance`, when finishing a proposal which
		// is not the last passed proposal, it will change the sequence. So in here we must first executes all
		// passed proposals, and then finish then all.
		pIds := make([]*big.Int, 0, proposalCount)
		for i := uint32(0); i < proposalCount; i++ {
			prop, err := p.getPassedProposalByIndex(chain, header, state, i)
			if err != nil {
				return err
			}
			// execute the system governance Proposal
			tx := (*systemTxs)[int(i)]
			receipt, err := p.replayProposal(chain, header, state, prop, len(*txs), tx)
			if err != nil {
				return err
			}
			*txs = append(*txs, tx)
			*receipts = append(*receipts, receipt)
			// set
			pIds = append(pIds, prop.Id)
		}
		// Finish all proposal
		for i := uint32(0); i < proposalCount; i++ {
			err = p.finishProposalById(chain, header, state, pIds[i])
			if err != nil {
				return err
			}
		}
	}
	//TODO: 获取质押合约的参数

	realTeamRate, realValRate := p.getDistributeRate(chain, header)
	tmpTeamAddress, err := p.getTeamAddress(chain, header)
	if err == nil {
		if tmpTeamAddress.String() != header.TeamAddress.String() {
			log.Error("invalid team address", "team", header.TeamAddress.String(), "expect team address", tmpTeamAddress.String())
			return errInvalidTeamAddr
		}
	}
	providerLuckyData, err := p.getProviderInfo(chain, header)
	if err != nil {
		log.Error("get provider info failed", "error", err.Error())
	}

	tmpProvider := common.Address{}
	totalVote := big.NewInt(0)
	for _, k := range providerLuckyData {
		totalVote.Add(totalVote, k.VotingPower)
	}
	if totalVote.Cmp(common.Big0) > 0 {
		parentHeader := chain.GetHeaderByHash(header.ParentHash)

		if parentHeader != nil {
			calRlp, err := rlp.EncodeToBytes([]interface{}{parentHeader.Root, header.ParentHash, parentHeader.Coinbase, parentHeader.Time})
			if err != nil {
				return err
			}

			calHash := crypto.Keccak256(calRlp)
			magicNumber := big.NewInt(0).SetBytes(calHash)
			magicNumber.Mod(magicNumber, totalVote)
			currentVote := big.NewInt(0)
			for _, v := range providerLuckyData {
				currentVote.Add(currentVote, v.VotingPower)
				if magicNumber.Cmp(currentVote) < 0 {
					tmpProvider.SetBytes(v.ProviderAddress.Bytes())
					log.Debug("Check provider", "header Number", header.Number.String(), "provider", v.ProviderAddress, "votepower", v.VotingPower, "currentVote", currentVote)
					break
				}
			}
			if header.Provider.String() != tmpProvider.String() {
				log.Error("invalid provider", "provider", header.Provider.String(), "expect provider", tmpProvider.String())
				return errInvalidProvider
			}

		} else {
			log.Debug("header not exist,skip verify", "header number", header.Number)
		}
	} else {
		tmpProvider = common.Address{}
		if header.Provider.String() != tmpProvider.String() {
			log.Error("invalid provider", "provider", header.Provider.String(), "expect provider", tmpProvider.String())
			return errInvalidProvider
		}

	}

	if header.TeamRate != realTeamRate || header.ValidatorRate != realValRate {
		return errInvalidDistributeRate
	}
	//if header.Difficulty.Cmp(diffInTurn) != 0 {
	//		spoiledVal := snap.supposeValidator()
	//		signedRecently := false
	//		for _, recent := range snap.Recents {
	//			if recent == spoiledVal {
	//				signedRecently = true
	//				break
	//			}
	//		}
	//		if !signedRecently {
	//			log.Trace("slash validator", "block hash", header.Hash(), "address", spoiledVal)
	//			err = p.slash(spoiledVal, state, header, cx, txs, receipts, systemTxs, usedGas, false)
	//			if err != nil {
	//				// it is possible that slash validator failed because of the slash channel is disabled.
	//				log.Error("slash validator failed", "block hash", header.Hash(), "address", spoiledVal)
	//			}
	//		}
	//	}
	//	val := header.Coinbase
	//	err = p.distributeIncoming(val, state, header, cx, txs, receipts, systemTxs, usedGas, false)
	//	if err != nil {
	//		return err
	//	}
	//	if len(*systemTxs) > 0 {
	//		return errors.New("the length of systemTxs do not match")
	//	}
	// No block rewards in PoA, so the state remains as is and uncles are dropped
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = types.CalcUncleHash(nil)

	return nil
}

func (p *Dpos) TryCreateChallenge(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB) (*types.Transaction, uint64, common.Address, error, int) {
	//cx := chainContext{Chain: chain, dpos: p}

	if chain.Config().Dpos.Por == true {
		//if header.Number.Uint64()%p.config.Epoch == 0 {
		if header.Number.Uint64()%p.config.Epoch != 0 {
			if rand.Intn(100000) < challengeRate {
				chooseProvider, isPunish, err := p.getCanChallengeProvider(chain, header)
				if err == nil && chooseProvider != nil {
					whetherCan := p.whetherCanPor(chain, header, *chooseProvider, isPunish)
					if whetherCan == 1 {
						seed := uint64(rand.Int63n(maxSeedInt))
						seedBytes := [8]byte{}
						binary.LittleEndian.PutUint64(seedBytes[:], seed)
						seedHash := crypto.Keccak256(seedBytes[:])
						tx, err := p.createChallengeTransaction(*chooseProvider, new(big.Int).SetBytes(seedHash), state, header)
						if err != nil {
							log.Error("unexcepted challenge error", "errors", err.Error())
						}
						return tx, seed, *chooseProvider, err, 1
					} else if whetherCan == -1 {
						tx, err := p.createNotSubmitTransaction(*chooseProvider, state, header)
						if err != nil {
							log.Error("unexcepted challenge error", "errors", err.Error())
						}
						fmt.Println("create not submit transaction")
						return tx, 0, *chooseProvider, err, 2
					}

				}
			}
		}
	}
	return nil, 0, common.Address{}, errors.New("not in challenge round"), 1
}

// FinalizeAndAssemble implements consensus.Engine, ensuring no uncles are set,
// nor block rewards given, and returns the final block.
func (p *Dpos) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB,
	txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (b *types.Block, rs []*types.Receipt, err error) {
	defer func() {
		if err != nil {
			log.Warn("FinalizeAndAssemble failed", "err", err)
		}
	}()
	// Initialize all system contracts at block 1.
	if header.Number.Cmp(common.Big1) == 0 {
		if err := p.initializeSystemContracts(chain, header, state); err != nil {

			panic(err)
		}
	}
	if err := p.tryPunishValidator(chain, header, state); err != nil {

		panic(err)
	}

	if err := p.punishProvider(chain, header, state); err != nil {
		panic(err)
	}
	if header.Number.Cmp(common.Big3) > 0 {
		if err := p.trySendBlockReward(chain, header, state); err != nil {

			panic(err)
		}
	}

	//}

	// do epoch thing at the end, because it will update active validators
	if header.Number.Uint64()%p.config.Epoch == 0 {
		if _, err := p.doSomethingAtEpoch(chain, header, state); err != nil {

			panic(err)
		}
	}

	//handle system governance Proposal
	//
	// Note:
	// Even if the miner is not `running`, it's still working,
	// the 'miner.worker' will try to FinalizeAndAssemble a block,
	// in this case, the signTxFn is not set. A `non-miner node` can't execute system governance proposal.
	if p.signTxFn != nil && chain.Config().IsRedCoast(header.Number) {
		proposalCount, err := p.getPassedProposalCount(chain, header, state)
		if err != nil {

			return nil, nil, err
		}

		// Due to the logics of the finish operation of contract `governance`, when finishing a proposal which
		// is not the last passed proposal, it will change the sequence. So in here we must first executes all
		// passed proposals, and then finish then all.
		pIds := make([]*big.Int, 0, proposalCount)
		for i := uint32(0); i < proposalCount; i++ {
			prop, err := p.getPassedProposalByIndex(chain, header, state, i)
			if err != nil {

				return nil, nil, err
			}
			// execute the system governance Proposal
			tx, receipt, err := p.executeProposal(chain, header, state, prop, len(txs))
			if err != nil {

				return nil, nil, err
			}
			txs = append(txs, tx)
			receipts = append(receipts, receipt)
			// set
			pIds = append(pIds, prop.Id)
		}
		// Finish all proposal
		for i := uint32(0); i < proposalCount; i++ {
			err = p.finishProposalById(chain, header, state, pIds[i])
			if err != nil {

				return nil, nil, err
			}
		}
	}

	// No block rewards in PoA, so the state remains as is and uncles are dropped
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = types.CalcUncleHash(nil)

	// Assemble and return the final block for sealing

	return types.NewBlock(header, txs, nil, receipts, new(trie.Trie)), receipts, nil
	// No block rewards in PoA, so the state remains as is and uncles are dropped
	//	cx := chainContext{Chain: chain, dpos: p}
	//	if txs == nil {
	//		txs = make([]*types.Transaction, 0)
	//	}
	//	if receipts == nil {
	//		receipts = make([]*types.Receipt, 0)
	//	}
	//	if header.Number.Cmp(common.Big1) == 0 {
	//		err := p.initContract(state, header, cx, &txs, &receipts, nil, &header.GasUsed, true)
	//		if err != nil {
	//			log.Error("init contract failed")
	//		}
	//	}
	//	if header.Difficulty.Cmp(diffInTurn) != 0 {
	//		number := header.Number.Uint64()
	//		snap, err := p.snapshot(chain, number-1, header.ParentHash, nil)
	//		if err != nil {
	//			return nil, nil, err
	//		}
	//		spoiledVal := snap.supposeValidator()
	//		signedRecently := false
	//		for _, recent := range snap.Recents {
	//			if recent == spoiledVal {
	//				signedRecently = true
	//				break
	//			}
	//		}
	//		if !signedRecently {
	//			err = p.slash(spoiledVal, state, header, cx, &txs, &receipts, nil, &header.GasUsed, true)
	//			if err != nil {
	//				// it is possible that slash validator failed because of the slash channel is disabled.
	//				log.Error("slash validator failed", "block hash", header.Hash(), "address", spoiledVal)
	//			}
	//		}
	//	}
	//	err := p.distributeIncoming(p.val, state, header, cx, &txs, &receipts, nil, &header.GasUsed, true)
	//	if err != nil {
	//		return nil, nil, err
	//	}
	//	// should not happen. Once happen, stop the node is better than broadcast the block
	//	if header.GasLimit < header.GasUsed {
	//		return nil, nil, errors.New("gas consumption of system txs exceed the gas limit")
	//	}
	//	header.UncleHash = types.CalcUncleHash(nil)
	//	var blk *types.Block
	//	var rootHash common.Hash
	//	wg := sync.WaitGroup{}
	//	wg.Add(2)
	//	go func() {
	//		rootHash = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	//		wg.Done()
	//	}()
	//	go func() {
	//		blk = types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil))
	//		wg.Done()
	//	}()
	//	wg.Wait()
	//	blk.SetRoot(rootHash)
	//	// Assemble and return the final block for sealing
	//	return blk, receipts, nil
}

func getBlockReward(blockNumber uint64) *big.Int {
	yearBlockNumber := uint64(yearBlockCount)
	//yearBlockNumber := uint64(1440)
	blockReward := new(big.Int).Mul(big.NewInt(blockDistributeRewrad), big.NewInt(1e8))
	if blockNumber <= yearBlockNumber {
		return blockReward
	}
	blockReward.Div(blockReward, big.NewInt(2))
	if blockNumber <= yearBlockNumber*3 {
		return blockReward
	}
	halvingTimes := int64((int64(blockNumber)-int64(yearBlockNumber)*3-1)/int64(yearBlockNumber*3)) + 1
	//log.Info("halving time ", "halvingTimes", halvingTimes)
	for i := 0; i < int(halvingTimes); i++ {
		blockReward.Div(blockReward, big.NewInt(2))
	}
	return blockReward
}

func (p *Dpos) trySendBlockReward(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB) error {
	fee := state.GetBalance(consensus.SystemAddress)
	/*
		if fee.Cmp(common.Big0) <= 0 {
			return nil
		}
	*/
	// Miner will send tx to deposit block fees to contract, add to his balance first.

	if header.Number.Uint64() > common.BigOneDayUint {
		yestBlockNumber := header.Number.Uint64() - common.BigOneDayUint
		reward := getBlockReward(yestBlockNumber)
		yestHeader := chain.GetHeaderByNumber(yestBlockNumber)

		lastReward := new(big.Int).Div(reward, big.NewInt(2))
		if yestHeader != nil {
			TeamAddress := yestHeader.TeamAddress
			teamPartReward := new(big.Int).Div(new(big.Int).Mul(reward, new(big.Int).SetUint64(yestHeader.TeamRate)), big.NewInt(doubleAllPercent))
			lastReward.Sub(lastReward, teamPartReward)

			validatorPartReward := new(big.Int).Div(new(big.Int).Mul(reward, new(big.Int).SetUint64(yestHeader.ValidatorRate)), big.NewInt(doubleAllPercent))
			lastReward.Sub(lastReward, validatorPartReward)
			if lastReward.Cmp(common.Big0) > 0 {
				if (yestHeader.Provider != common.Address{}) {
					state.AddBalance(yestHeader.Provider, lastReward)
					state.AddLockBalance(yestHeader.Provider, teamPartReward)
				}
				state.AddBalance(TeamAddress, teamPartReward)
				state.AddLockBalance(TeamAddress, teamPartReward)
				state.AddBalance(yestHeader.Coinbase, validatorPartReward)
				state.AddLockBalance(yestHeader.Coinbase, validatorPartReward)

			}
			//log.Info("distribute reward ", "teamPartReward", teamPartReward, "validatorPartReward", validatorPartReward, "lastReward", lastReward, "lastHeader.Provider", yestHeader.Provider, "lastHeader.Number", yestBlockNumber)
			for i := 0; i < distributeRound; i++ {
				lastNumber := header.Number.Uint64() - common.BigOneDayUint*uint64(i+2)
				if lastNumber > header.Number.Uint64() || (lastNumber == 0) {
					//log.Info("max pay count", "count", i, "header.Number.Uint64()", header.Number.Uint64())
					break
				}
				lastHeader := chain.GetHeaderByNumber(lastNumber)

				if lastHeader != nil {
					reward = getBlockReward(lastNumber)
					lastReward = new(big.Int).Div(reward, big.NewInt(doubleDistributeRound))
					teamPartReward := new(big.Int).Div(new(big.Int).Div(new(big.Int).Mul(reward, new(big.Int).SetUint64(yestHeader.TeamRate)), big.NewInt(doubleAllPercent)), big.NewInt(distributeRound))
					lastReward.Sub(lastReward, teamPartReward)
					validatorPartReward := new(big.Int).Div(new(big.Int).Div(new(big.Int).Mul(reward, new(big.Int).SetUint64(yestHeader.ValidatorRate)), big.NewInt(doubleAllPercent)), big.NewInt(distributeRound))
					lastReward.Sub(lastReward, validatorPartReward)
					if lastReward.Cmp(common.Big0) > 0 {
						if (lastHeader.Provider != common.Address{}) {
							state.AddBalance(lastHeader.Provider, lastReward)
							if state.GetLockBalance(lastHeader.Provider).Cmp(lastReward) > 0 {
								state.SubLockBalance(lastHeader.Provider, lastReward)
							} else {
								state.SetLockBalance(lastHeader.Provider, common.Big0)
							}

						}
						state.AddBalance(TeamAddress, teamPartReward)
						if state.GetLockBalance(TeamAddress).Cmp(teamPartReward) > 0 {
							state.SubLockBalance(TeamAddress, teamPartReward)
						} else {
							state.SetLockBalance(TeamAddress, common.Big0)
						}

						state.AddBalance(lastHeader.Coinbase, validatorPartReward)
						if state.GetLockBalance(lastHeader.Coinbase).Cmp(validatorPartReward) > 0 {
							state.SubLockBalance(lastHeader.Coinbase, validatorPartReward)
						} else {
							state.SetLockBalance(lastHeader.Coinbase, common.Big0)
						}

						//log.Info("distribute reward ","teamPartReward",teamPartReward,"validatorPartReward",validatorPartReward,"lastReward",lastReward,"lastHeader.Provider",lastHeader.Provider,"lastHeader.Number",lastNumber)
					}
				} else {
					log.Error("unexpect error block header not found.", "lastNumber", lastNumber)
				}

			}

		}
	}

	state.AddBalance(common.Address{}, fee)
	// reset fee
	state.SetBalance(consensus.SystemAddress, common.Big0)

	//method := "distributeBlockReward"
	//data, err := p.abi[systemcontract.DposFactoryContractName].Pack(method)
	//if err != nil {
	//	log.Error("Can't pack data for distributeBlockReward", "err", err)
	//	return err
	//}
	//
	//nonce := state.GetNonce(header.Coinbase)
	//msg := types.NewMessage(header.Coinbase, systemcontract.GetValidatorAddr(header.Number, p.chainConfig), nonce, reward, math.MaxUint64, new(big.Int), data, nil, true)
	//
	//if _, err := vmcaller.ExecuteMsg(msg, state, header, newChainContext(chain, p), p.chainConfig); err != nil {
	//	return err
	//}

	return nil
}

func (p *Dpos) tryPunishValidator(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB) error {
	number := header.Number.Uint64()
	snap, err := p.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	validators := snap.validators()
	outTurnValidator := validators[number%uint64(len(validators))]
	// check sigend recently or not
	signedRecently := false
	for _, recent := range snap.Recents {
		if recent == outTurnValidator {
			signedRecently = true
			break
		}
	}
	if !signedRecently {
		if err := p.punishValidator(outTurnValidator, chain, header, state); err != nil {
			return err
		}
	} else {
		outTurnValidator = common.HexToAddress("0x0000000000000000000000000000000000000000")
		if err := p.punishValidator(outTurnValidator, chain, header, state); err != nil {
			return err
		}
	}

	return nil
}

func (p *Dpos) CreateChallengeFinish(validator common.Address, provider common.Address, seed uint64, challengeAmount uint64, rootHash *big.Int, challengeState int, nonceDiff uint64, state *state.StateDB, header *types.Header) (*types.Transaction, error) {
	// method
	method := "challengeFinish"

	// get packed data
	data, err := p.abi[systemcontract.ValidatorFactoryContractName].Pack(method,
		provider, new(big.Int).SetUint64(seed), new(big.Int).SetUint64(challengeAmount), rootHash, uint8(challengeState))
	if err != nil {
		log.Error("Unable to pack tx for deposit", "error", err)
		return nil, err
	}
	// get system message
	msg := p.getSystemMessage(header.Coinbase, systemcontract.ValidatorFactoryContractAddr, data, common.Big0)
	// apply message
	nonce := state.GetNonce(msg.From()) + nonceDiff
	expectedTx := types.NewTransaction(nonce, *msg.To(), msg.Value(), defaultGasLimit, msg.GasPrice(), msg.Data())
	//expectedHash := p.signer.Hash(expectedTx)
	expectedTx, err = p.signTxFns[validator](accounts.Account{Address: msg.From()}, expectedTx, p.chainConfig.ChainID)
	if err != nil {
		return nil, err
	}

	return expectedTx, nil
}

func (p *Dpos) createNotSubmitTransaction(provider common.Address, state *state.StateDB, header *types.Header) (*types.Transaction, error) {

	// method
	method := "validatorNotSubmitResult"

	// get packed data
	data, err := p.abi[systemcontract.ValidatorFactoryContractName].Pack(method,
		provider)
	if err != nil {
		log.Error("Unable to pack tx for deposit", "error", err)
		return nil, err
	}
	// get system message
	msg := p.getSystemMessage(header.Coinbase, systemcontract.ValidatorFactoryContractAddr, data, common.Big0)
	// apply message
	nonce := state.GetNonce(msg.From())
	expectedTx := types.NewTransaction(nonce, *msg.To(), msg.Value(), defaultGasLimit, msg.GasPrice(), msg.Data())
	//expectedHash := p.signer.Hash(expectedTx)
	expectedTx, err = p.signTxFns[header.Coinbase](accounts.Account{Address: msg.From()}, expectedTx, p.chainConfig.ChainID)

	if err != nil {
		return nil, err
	}

	return expectedTx, nil

}
func (p *Dpos) createChallengeTransaction(provider common.Address, seedHash *big.Int, state *state.StateDB, header *types.Header) (*types.Transaction, error) {

	// method
	method := "challengeProvider"

	// get packed data
	data, err := p.abi[systemcontract.ValidatorFactoryContractName].Pack(method,
		provider, seedHash, p.config.ChallengeCommitUrl,
	)
	if err != nil {
		log.Error("Unable to pack tx for deposit", "error", err)
		return nil, err
	}
	// get system message
	msg := p.getSystemMessage(header.Coinbase, systemcontract.ValidatorFactoryContractAddr, data, common.Big0)
	// apply message
	nonce := state.GetNonce(msg.From())
	expectedTx := types.NewTransaction(nonce, *msg.To(), msg.Value(), defaultGasLimit, msg.GasPrice(), msg.Data())
	//expectedHash := p.signer.Hash(expectedTx)
	expectedTx, err = p.signTxFns[header.Coinbase](accounts.Account{Address: msg.From()}, expectedTx, p.chainConfig.ChainID)

	if err != nil {
		return nil, err
	}

	return expectedTx, nil

}

func (p *Dpos) doSomethingAtEpoch(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB) ([]common.Address, error) {
	newSortedValidators, err := p.getTopValidators(chain, header)
	if err != nil {
		return []common.Address{}, err
	}

	// update contract new validators if new set exists
	//if err := p.updateValidators(newSortedValidators, chain, header, state); err != nil {
	//	return []common.Address{}, err
	//}
	//  decrease validator missed blocks counter at epoch
	/*
		if err := p.decreaseMissedBlocksCounter(chain, header, state); err != nil {
			return []common.Address{}, err
		}*/

	return newSortedValidators, nil
}

// initializeSystemContracts initializes all genesis system contracts.
func (p *Dpos) initializeSystemContracts(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB) error {
	//fmt.Println("initializeSystemContracts")
	snap, err := p.snapshot(chain, 0, header.ParentHash, nil)
	if err != nil {
		return err
	}

	genesisValidators := snap.validators()
	if len(genesisValidators) == 0 || len(genesisValidators) > maxValidators {
		return errInvalidValidatorsLength
	}

	method := "initialize"

	contracts := []struct {
		addr    common.Address
		packFun func() ([]byte, error)
	}{

		{systemcontract.ValidatorFactoryContractAddr, func() ([]byte, error) {

			return p.abi[systemcontract.ValidatorFactoryContractName].Pack(method, genesisValidators, systemcontract.GetValidatorAdmin(p.chainConfig.ChainID))
		}},
		{systemcontract.ProviderFactoryContractAddr, func() ([]byte, error) {
			return p.abi[systemcontract.ProviderFactoryContractName].Pack(method, systemcontract.GetValidatorAdmin(p.chainConfig.ChainID))
		}},
		{systemcontract.AddressListContractAddr, func() ([]byte, error) {
			return p.abi[systemcontract.AddressListContractName].Pack(method, systemcontract.GetAddressListAdmin(p.chainConfig.ChainID))
		}},

		/*
			{systemcontract.PunishV1ContractAddr, func() ([]byte, error) { return p.abi[systemcontract.PunishV1ContractName].Pack(method) }},
			{systemcontract.SysGovContractAddr, func() ([]byte, error) {
				return p.abi[systemcontract.SysGovContractName].Pack(method, systemcontract.FactoryAdminAddr)
			}},
			{systemcontract.DposFactoryContractAddr, func() ([]byte, error) {
				return p.abi[systemcontract.DposFactoryContractName].Pack(method, genesisValidators, systemcontract.FactoryAdminAddr)
			}},*/
	}
	i := 0
	for _, contract := range contracts {
		i += 1
		data, err := contract.packFun()
		if err != nil {
			return err
		}
		nonce := state.GetNonce(header.Coinbase)
		msg := types.NewMessage(header.Coinbase, &contract.addr, nonce, new(big.Int), math.MaxUint64, new(big.Int), data, nil, true)
		//fmt.Println("init",contract.addr,data)
		if result, err := vmcaller.ExecuteMsg(msg, state, header, newChainContext(chain, p), p.chainConfig); err != nil {
			return err
		} else {
			fmt.Println("vv is ", hex.EncodeToString(result))
		}

	}

	return nil
}

// call this at epoch block to get top validators based on the state of epoch block - 1
func (p *Dpos) getTopValidators(chain consensus.ChainHeaderReader, header *types.Header) ([]common.Address, error) {
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return []common.Address{}, consensus.ErrUnknownAncestor
	}
	statedb, err := p.stateFn(parent.Root)
	if err != nil {
		return []common.Address{}, err
	}

	method := "getAllActiveValidatorAddr"
	data, err := p.abi[systemcontract.ValidatorFactoryContractName].Pack(method)
	if err != nil {
		log.Error("Can't pack data for getAllActiveValidatorAddr", "error", err)
		return []common.Address{}, err
	}

	msg := types.NewMessage(header.Coinbase, systemcontract.GetValidatorAddr(parent.Number, p.chainConfig), 0, new(big.Int), math.MaxUint64, new(big.Int), data, nil, false)

	// use parent
	result, err := vmcaller.ExecuteMsg(msg, statedb, parent, newChainContext(chain, p), p.chainConfig)
	if err != nil {
		return []common.Address{}, err
	}

	// unpack data
	ret, err := p.abi[systemcontract.ValidatorFactoryContractName].Unpack(method, result)
	if err != nil {
		return []common.Address{}, err
	}
	if len(ret) != 1 {
		return []common.Address{}, errors.New("Invalid params length")
	}
	validators, ok := ret[0].([]common.Address)
	if !ok {
		return []common.Address{}, errors.New("Invalid validators format")
	}
	sort.Sort(validatorsAscending(validators))
	return validators, err
}

// call this to get distribute rate
func (p *Dpos) getDistributeRate(chain consensus.ChainHeaderReader, header *types.Header) (uint64, uint64) {
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return 400, 1000
	}

	statedb, err := p.stateFn(parent.Root)
	if err != nil {
		return 400, 1000
	}

	method := "team_percent"
	data, err := p.abi[systemcontract.ValidatorFactoryContractName].Pack(method)
	if err != nil {
		log.Error("Can't pack data for team_percent", "error", err)
		return 400, 1000
	}

	msg := types.NewMessage(header.Coinbase, systemcontract.GetValidatorAddr(parent.Number, p.chainConfig), 0, new(big.Int), math.MaxUint64, new(big.Int), data, nil, false)

	// use parent
	result, err := vmcaller.ExecuteMsg(msg, statedb, parent, newChainContext(chain, p), p.chainConfig)
	if err != nil {
		return 400, 1000
	}

	// unpack data
	ret, err := p.abi[systemcontract.ValidatorFactoryContractName].Unpack(method, result)

	if err != nil {
		return 400, 1000
	}
	if len(ret) != 1 {
		return 400, 1000
	}
	teamRate, ok := ret[0].(*big.Int)
	if !ok {
		return 400, 1000
	}

	method = "validator_percent"
	data, err = p.abi[systemcontract.ValidatorFactoryContractName].Pack(method)
	if err != nil {
		log.Error("Can't pack data for validator_percent", "error", err)
		return 400, 1000
	}

	msg = types.NewMessage(header.Coinbase, systemcontract.GetValidatorAddr(parent.Number, p.chainConfig), 0, new(big.Int), math.MaxUint64, new(big.Int), data, nil, false)

	// use parent
	result, err = vmcaller.ExecuteMsg(msg, statedb, parent, newChainContext(chain, p), p.chainConfig)
	if err != nil {
		return 400, 1000
	}

	// unpack data
	ret, err = p.abi[systemcontract.ValidatorFactoryContractName].Unpack(method, result)

	if err != nil {
		return 400, 1000
	}
	if len(ret) != 1 {
		return 400, 1000
	}
	valRate, ok := ret[0].(*big.Int)
	if !ok {
		return 400, 1000
	}

	return teamRate.Uint64(), valRate.Uint64()
}

func (p *Dpos) getTeamAddress(chain consensus.ChainHeaderReader, header *types.Header) (common.Address, error) {

	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return common.Address{}, consensus.ErrUnknownAncestor
	}

	statedb, err := p.stateFn(parent.Root)
	if err != nil {
		return common.Address{}, err
	}

	method := "team_address"
	data, err := p.abi[systemcontract.ValidatorFactoryContractName].Pack(method)
	if err != nil {
		log.Error("Can't pack data for team_address", "error", err)
		return common.Address{}, err
	}

	msg := types.NewMessage(header.Coinbase, systemcontract.GetValidatorAddr(parent.Number, p.chainConfig), 0, new(big.Int), math.MaxUint64, new(big.Int), data, nil, false)

	// use parent
	result, err := vmcaller.ExecuteMsg(msg, statedb, parent, newChainContext(chain, p), p.chainConfig)
	if err != nil {
		return common.Address{}, err
	}

	// unpack data
	ret, err := p.abi[systemcontract.ValidatorFactoryContractName].Unpack(method, result)

	if err != nil {
		return common.Address{}, err
	}
	if len(ret) != 1 {
		return common.Address{}, err
	}
	teamAddress, ok := ret[0].(common.Address)
	if !ok {
		return common.Address{}, err
	}
	return teamAddress, nil
}

// call this at every block to get provider Info.
func (p *Dpos) getProviderInfo(chain consensus.ChainHeaderReader, header *types.Header) ([]VoteInfo, error) {
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return []VoteInfo{}, consensus.ErrUnknownAncestor
	}
	statedb, err := p.stateFn(parent.Root)
	if err != nil {
		return []VoteInfo{}, err
	}
	//if ProviderFactoryAddr == (common.Address{}) {
	//	method := "providerFactory"
	//	data, err := p.abi[systemcontract.ValidatorFactoryContractName].Pack(method)
	//	if err != nil {
	//		log.Error("Can't pack data for providerFactory", "error", err)
	//		return []VoteInfo{}, err
	//	}
	//
	//	msg := types.NewMessage(header.Coinbase, systemcontract.GetValidatorAddr(parent.Number, p.chainConfig), 0, new(big.Int), math.MaxUint64, new(big.Int), data, nil, false)
	//	result, err := vmcaller.ExecuteMsg(msg, statedb, parent, newChainContext(chain, p), p.chainConfig)
	//	if err != nil {
	//		return []VoteInfo{}, err
	//	}
	//	ret, err := p.abi[systemcontract.ValidatorFactoryContractName].Unpack(method, result)
	//	if err != nil {
	//		return []VoteInfo{}, err
	//	}
	//	ProviderFactoryAddr = ret[0].(common.Address)
	//
	//}
	//if ProviderFactoryAddr == (common.Address{}) {
	//	return []VoteInfo{}, nil
	//}
	method := "getProviderInfo"
	data, err := p.abi[systemcontract.ProviderFactoryContractName].Pack(method, big.NewInt(0), big.NewInt(0))
	if err != nil {
		log.Error("Can't pack data for getAllActiveValidatorAddr", "error", err)
		return []VoteInfo{}, err
	}

	msg := types.NewMessage(header.Coinbase, &(systemcontract.ProviderFactoryContractAddr), 0, new(big.Int), math.MaxUint64, new(big.Int), data, nil, false)

	// use parent
	result, err := vmcaller.ExecuteMsg(msg, statedb, parent, newChainContext(chain, p), p.chainConfig)
	if err != nil {
		return []VoteInfo{}, err
	}

	defer func() {
		r := recover()
		if r != nil {
			//fmt.Println("panic error",r)
			err = fmt.Errorf("recover from panic: %v", r)

		}

	}()

	// unpack data
	ret, err := p.abi[systemcontract.ProviderFactoryContractName].Unpack(method, result)
	if err != nil {
		return []VoteInfo{}, err
	}
	if len(ret) != 1 {
		return []VoteInfo{}, errors.New("Invalid params length")
	}

	providers := *abi.ConvertType(ret[0], new([]ProviderInfos)).(*[]ProviderInfos)

	//fmt.Println(ret)
	//providers, ok := ret[0].([]ProviderInfos)
	//if !ok {
	//	return []VoteInfo{}, errors.New("Invalid provider format")
	//}
	rets := make([]VoteInfo, 0, 0)

	for _, oneProvider := range providers {
		if oneProvider.Info.State != Running {
			continue
		}
		handleCpuCount := new(big.Int).Div(oneProvider.Info.Total.CpuCount, common.Big1000)
		handleMemory := new(big.Int).Div(oneProvider.Info.Total.MemoryCount, fourGMem)
		handleCount := handleCpuCount
		if handleMemory.Cmp(handleCpuCount) < 0 {
			handleCount = handleMemory
		}
		if oneProvider.MarginAmount.Cmp(new(big.Int).Mul(StakeThreshold, handleCount)) < 0 {
			continue
		}

		cpuDiff := new(big.Int).Sub(oneProvider.Info.Total.CpuCount, oneProvider.Info.Lock.CpuCount)
		storageDiff := new(big.Int).Div(new(big.Int).Sub(oneProvider.Info.Total.StorageCount, oneProvider.Info.Lock.StorageCount), big.NewInt(oneTDiv1000))
		memoryDiff := new(big.Int).Div(new(big.Int).Sub(oneProvider.Info.Total.MemoryCount, oneProvider.Info.Lock.MemoryCount), big.NewInt(oneGDiv1000))
		tmpMaxStorage := new(big.Int).Mul(MaxStorage, cpuDiff)
		if storageDiff.Cmp(tmpMaxStorage) > 0 {
			storageDiff.Set(tmpMaxStorage)
		}
		tmpMaxMemory := new(big.Int).Mul(MaxMemory, cpuDiff)
		if memoryDiff.Cmp(tmpMaxMemory) > 0 {
			memoryDiff.Set(tmpMaxMemory)
		}
		tmpPorValue := new(big.Int).Mul(new(big.Int).Add(cpuDiff, new(big.Int).Add(storageDiff, memoryDiff)), big.NewInt(1e16))
		luckValue := new(big.Int).Add(new(big.Int).Mul(oneProvider.MarginAmount, LuckyRate), new(big.Int).Mul(tmpPorValue, LuckyPorRate))
		tmpVoteInfo := VoteInfo{VotingPower: luckValue, ProviderAddress: oneProvider.Info.Owner}
		rets = append(rets, tmpVoteInfo)
	}

	return rets, err
}

// call this at every epoch  to get provider list.
func (p *Dpos) getCanChallengeProvider(chain consensus.ChainHeaderReader, header *types.Header) (*common.Address, bool, error) {
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	var ok = false
	if parent == nil {
		return nil, ok, consensus.ErrUnknownAncestor
	}
	statedb, err := p.stateFn(parent.Root)
	if err != nil {
		return nil, ok, err
	}

	method := "getProviderInfo"
	data, err := p.abi[systemcontract.ProviderFactoryContractName].Pack(method, big.NewInt(0), big.NewInt(0))
	if err != nil {
		log.Error("Can't pack data for getAllActiveValidatorAddr", "error", err)
		return nil, ok, err
	}

	msg := types.NewMessage(header.Coinbase, &(systemcontract.ProviderFactoryContractAddr), 0, new(big.Int), math.MaxUint64, new(big.Int), data, nil, false)

	// use parent
	result, err := vmcaller.ExecuteMsg(msg, statedb, parent, newChainContext(chain, p), p.chainConfig)
	if err != nil {
		return nil, ok, err
	}

	defer func() {
		r := recover()
		if r != nil {
			fmt.Println("panic error", r)
			err = fmt.Errorf("recover from panic: %v", r)

		}

	}()
	// unpack data
	ret, err := p.abi[systemcontract.ProviderFactoryContractName].Unpack(method, result)
	if err != nil {
		return nil, ok, err
	}
	if len(ret) != 1 {
		return nil, ok, errors.New("Invalid params length")
	}

	providers := *abi.ConvertType(ret[0], new([]ProviderInfos)).(*[]ProviderInfos)

	//fmt.Println(ret)
	//providers, ok := ret[0].([]ProviderInfos)
	//if !ok {
	//	return []VoteInfo{}, errors.New("Invalid provider format")
	//}
	rets := make([]common.Address, 0, 0)
	punishList := make(map[common.Address]bool, 0)
	for _, oneProvider := range providers {

		if oneProvider.Info.State == Pause || oneProvider.Info.State == Stop {
			continue
		}
		if oneProvider.Info.State == Running {
			handleCpuCount := new(big.Int).Div(oneProvider.Info.Total.CpuCount, common.Big1000)
			handleMemory := new(big.Int).Div(oneProvider.Info.Total.MemoryCount, fourGMem)
			handleCount := handleCpuCount
			if handleMemory.Cmp(handleCpuCount) < 0 {
				handleCount = handleMemory
			}
			if oneProvider.MarginAmount.Cmp(new(big.Int).Mul(StakeThreshold, handleCount)) < 0 {
				continue
			}
		}
		if oneProvider.Info.State == Punish {
			if oneProvider.MarginAmount.Cmp(common.Big1) < 0 {
				continue
			}
			punishList[oneProvider.Info.Owner] = true
		}

		cpuDiff := new(big.Int).Sub(oneProvider.Info.Total.CpuCount, oneProvider.Info.Used.CpuCount)
		memoryDiff := new(big.Int).Sub(oneProvider.Info.Total.MemoryCount, oneProvider.Info.Used.MemoryCount)

		if cpuDiff.Cmp(common.Big1000) >= 0 && memoryDiff.Cmp(fourGMem) >= 0 {
			rets = append(rets, oneProvider.Info.Owner)
		}
	}
	index := rand.Intn(len(rets))
	_, ok = punishList[rets[index]]
	return &rets[index], ok, err
}

func (p *Dpos) getMaxChallengeTime(chain consensus.ChainHeaderReader, header *types.Header) *big.Int {
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return big.NewInt(720)
	}
	statedb, err := p.stateFn(parent.Root)
	if err != nil {
		return big.NewInt(720)
	}
	method := "max_challenge_time"
	data, err := p.abi[systemcontract.ValidatorFactoryContractName].Pack(method)
	if err != nil {
		log.Error("Can't pack data for getProviderChallengeInfo", "error", err)
		return big.NewInt(720)
	}

	msg := types.NewMessage(header.Coinbase, &(systemcontract.ValidatorFactoryContractAddr), 0, new(big.Int), math.MaxUint64, new(big.Int), data, nil, false)

	// use parent
	result, err := vmcaller.ExecuteMsg(msg, statedb, parent, newChainContext(chain, p), p.chainConfig)
	if err != nil {
		return big.NewInt(720)
	}
	ret, err := p.abi[systemcontract.ValidatorFactoryContractName].Unpack(method, result)
	if err != nil {
		return big.NewInt(720)
	}
	maxChallengeTime := *abi.ConvertType(ret[0], new(big.Int)).(*big.Int)

	return &maxChallengeTime

}

func (p *Dpos) whetherCanPor(chain consensus.ChainHeaderReader, header *types.Header, providerAddr common.Address, isPunish bool) int {
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return 0
	}
	statedb, err := p.stateFn(parent.Root)
	if err != nil {
		return 0
	}
	method := "getProviderChallengeInfo"
	data, err := p.abi[systemcontract.ValidatorFactoryContractName].Pack(method, providerAddr)
	if err != nil {
		log.Error("Can't pack data for getProviderChallengeInfo", "error", err)
		return 0
	}

	msg := types.NewMessage(header.Coinbase, &(systemcontract.ValidatorFactoryContractAddr), 0, new(big.Int), math.MaxUint64, new(big.Int), data, nil, false)

	// use parent
	result, err := vmcaller.ExecuteMsg(msg, statedb, parent, newChainContext(chain, p), p.chainConfig)
	if err != nil {
		return 0
	}

	defer func() {
		r := recover()
		if r != nil {
			fmt.Println("panic error", r)
			err = fmt.Errorf("recover from panic: %v", r)

		}

	}()
	// unpack data
	ret, err := p.abi[systemcontract.ValidatorFactoryContractName].Unpack(method, result)
	if err != nil {
		return 0
	}
	if len(ret) != 1 {
		return 0
	}
	var interval time.Duration
	if isPunish {
		interval = punishChallengeInterval
	} else {
		interval = challengeInterval
	}
	challengeInfo := *abi.ConvertType(ret[0], new(providerChallengeInfo)).(*providerChallengeInfo)

	maxChallengeTime := p.getMaxChallengeTime(chain, header)
	if challengeInfo.State == Create && (time.Now().Sub(time.Unix(challengeInfo.CreateChallengeTime.Int64(), 0))) > time.Second*time.Duration(2*maxChallengeTime.Int64()) {
		return -1
	}

	if time.Now().Sub(time.Unix(challengeInfo.CreateChallengeTime.Int64(), 0)) > interval && challengeInfo.State != Create {
		return 1
	}
	return 0
}

/*
	func (p *Dpos) updateValidators(vals []common.Address, chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB) error {
		// method
		method := "updateActiveValidatorSet"
		data, err := p.abi[systemcontract.DposFactoryContractName].Pack(method, vals, new(big.Int).SetUint64(p.config.Epoch))
		if err != nil {
			log.Error("Can't pack data for updateActiveValidatorSet", "error", err)
			return err
		}

		// call contract
		nonce := state.GetNonce(header.Coinbase)
		msg := types.NewMessage(header.Coinbase, systemcontract.GetValidatorAddr(header.Number, p.chainConfig), nonce, new(big.Int), math.MaxUint64, new(big.Int), data, nil, true)
		if _, err := vmcaller.ExecuteMsg(msg, state, header, newChainContext(chain, p), p.chainConfig); err != nil {
			log.Error("Can't update validators to contract", "err", err)
			return err
		}

		return nil
	}
*/
func (p *Dpos) punishValidator(val common.Address, chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB) error {
	// method
	method := "tryPunish"
	data, err := p.abi[systemcontract.ValidatorFactoryContractName].Pack(method, val)
	if err != nil {
		log.Error("Can't pack data for punish", "error", err)
		return err
	}

	// call contract
	nonce := state.GetNonce(header.Coinbase)
	msg := types.NewMessage(header.Coinbase, systemcontract.GetPunishAddr(header.Number, p.chainConfig), nonce, new(big.Int), math.MaxUint64, new(big.Int), data, nil, true)
	if _, err := vmcaller.ExecuteMsg(msg, state, header, newChainContext(chain, p), p.chainConfig); err != nil {
		log.Error("Can't punish validator", "err", err)
		return err
	}

	return nil
}
func (p *Dpos) punishProvider(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB) error {
	method := "tryPunish"
	punishProvider := common.HexToAddress("0x0000000000000000000000000000000000000000")
	data, err := p.abi[systemcontract.ProviderFactoryContractName].Pack(method, punishProvider)
	if err != nil {
		log.Error("Can't pack data for provider punish", "error", err)
		return err
	}
	// call contract
	nonce := state.GetNonce(header.Coinbase)
	msg := types.NewMessage(header.Coinbase, &systemcontract.ProviderFactoryContractAddr, nonce, new(big.Int), math.MaxUint64, new(big.Int), data, nil, true)
	if _, err := vmcaller.ExecuteMsg(msg, state, header, newChainContext(chain, p), p.chainConfig); err != nil {
		log.Error("Can't punish provider", "err", err)
		return err
	}

	return nil
}
func (p *Dpos) chooseChallengeProvider(provider common.Address, seed *big.Int, chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB) error {
	// method

	method := "challengeProvider"
	data, err := p.abi[systemcontract.ValidatorFactoryContractName].Pack(method, provider, seed, chain.Config().Dpos.ChallengeCommitUrl)
	if err != nil {
		log.Error("Can't pack data for punish", "error", err)
		return err
	}

	// call contract
	nonce := state.GetNonce(header.Coinbase)
	msg := types.NewMessage(header.Coinbase, &systemcontract.ValidatorFactoryContractAddr, nonce, new(big.Int), math.MaxUint64, new(big.Int), data, nil, true)
	if _, err := vmcaller.ExecuteMsg(msg, state, header, newChainContext(chain, p), p.chainConfig); err != nil {
		log.Error("Can't execute por challenge", "err", err)
		return err
	}

	return nil
}

/*
func (p *Dpos) decreaseMissedBlocksCounter(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB) error {
	// method
	method := "decreaseMissedBlocksCounter"
	data, err := p.abi[systemcontract.PunishV1ContractName].Pack(method, new(big.Int).SetUint64(p.config.Epoch))
	if err != nil {
		log.Error("Can't pack data for decreaseMissedBlocksCounter", "error", err)
		return err
	}

	// call contract
	nonce := state.GetNonce(header.Coinbase)
	msg := types.NewMessage(header.Coinbase, systemcontract.GetPunishAddr(header.Number, p.chainConfig), nonce, new(big.Int), math.MaxUint64, new(big.Int), data, nil, true)
	if _, err := vmcaller.ExecuteMsg(msg, state, header, newChainContext(chain, p), p.chainConfig); err != nil {
		log.Error("Can't decrease missed blocks counter for validator", "err", err)
		return err
	}

	return nil
}
*/
// Authorize injects a private key into the consensus engine to mint new blocks
// with.
func (p *Dpos) Authorize(val common.Address, signFn SignerFn, signTxFn SignerTxFn) bool {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.val = val
	if signFn != nil {
		p.signFn = signFn
		p.signTxFn = signTxFn
		p.signFns[val] = signFn
		p.signTxFns[val] = signTxFn

	} else {
		if signFn, ok := p.signFns[val]; ok {
			p.signFn = signFn
		} else {
			return false
		}
		if signTxFn, ok := p.signTxFns[val]; ok {
			p.signTxFn = signTxFn
		} else {
			return false
		}

	}

	return true
}

func (p *Dpos) SignSeed(header *types.Header, seed uint64) ([]byte, error) {

	return p.signFns[header.Coinbase](accounts.Account{Address: header.Coinbase}, accounts.MimetypeDpos, []byte(strconv.FormatUint(seed, 16)))
}

func (p *Dpos) Delay(chain consensus.ChainReader, header *types.Header) *time.Duration {
	number := header.Number.Uint64()
	snap, err := p.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return nil
	}
	delay := p.delayForRamanujanFork(snap, header)
	return &delay
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
func (p *Dpos) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	header := block.Header()

	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}
	// For 0-period chains, refuse to seal empty blocks (no reward but would spin sealing)
	if p.config.Period == 0 && len(block.Transactions()) == 0 {
		log.Info("Sealing paused, waiting for transactions")
		return nil
	}
	// Don't hold the val fields for the entire sealing procedure
	p.lock.RLock()
	val, signFn := p.val, p.signFn
	p.lock.RUnlock()

	snap, err := p.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}

	// Bail out if we're unauthorized to sign a block
	if _, authorized := snap.Validators[val]; !authorized {
		return errUnauthorizedValidator
	}

	// If we're amongst the recent signers, wait for the next block
	for seen, recent := range snap.Recents {
		if recent == val {
			// Signer is among recents, only wait if the current block doesn't shift it out
			if limit := uint64(len(snap.Validators)/2 + 1); number < limit || seen > number-limit {
				log.Info("Signed recently, must wait for others")
				return nil
			}
		}
	}

	// Sweet, the protocol permits us to sign the block, wait for our time
	delay := p.delayForRamanujanFork(snap, header)

	log.Info("Sealing block with", "number", number, "delay", delay, "headerDifficulty", header.Difficulty, "val", val.Hex())
	if header.Difficulty.Cmp(diffNoTurn) == 0 {
		// It's not our turn explicitly to sign, delay it a bit
		wiggle := time.Duration(len(snap.Validators)/2+1) * time.Second * time.Duration(wiggleTime)
		delay += time.Duration(rand.Int63n(int64(wiggle)))

		log.Trace("Out-of-turn signing requested", "wiggle", common.PrettyDuration(wiggle))
	}

	// Sign all the things!
	sig, err := signFn(accounts.Account{Address: val}, accounts.MimetypeDpos, DposRLP(header, p.chainConfig.ChainID))
	if err != nil {
		return err
	}
	copy(header.Extra[len(header.Extra)-extraSeal:], sig)

	// Wait until sealing is terminated or delay timeout.
	log.Trace("Waiting for slot to sign and propagate", "delay", common.PrettyDuration(delay))
	go func() {
		select {
		case <-stop:
			return
		case <-time.After(delay):
		}

		select {
		case results <- block.WithSeal(header):
		default:
			log.Warn("Sealing result is not read by miner", "sealhash", SealHash(header, p.chainConfig.ChainID))
		}
	}()

	return nil
}

func (p *Dpos) EnoughDistance(chain consensus.ChainReader, header *types.Header) bool {
	snap, err := p.snapshot(chain, header.Number.Uint64()-1, header.ParentHash, nil)
	if err != nil {
		return true
	}
	return snap.enoughDistance(p.val, header)
}

func (p *Dpos) IsLocalBlock(header *types.Header) bool {
	return p.val == header.Coinbase
}

func (p *Dpos) SignRecently(chain consensus.ChainReader, parent *types.Header) (bool, error) {
	snap, err := p.snapshot(chain, parent.Number.Uint64(), parent.ParentHash, nil)
	if err != nil {
		return true, err
	}

	// Bail out if we're unauthorized to sign a block
	if _, authorized := snap.Validators[p.val]; !authorized {
		return true, errUnauthorizedValidator
	}

	// If we're amongst the recent signers, wait for the next block
	number := parent.Number.Uint64() + 1
	for seen, recent := range snap.Recents {
		if recent == p.val {
			// Signer is among recents, only wait if the current block doesn't shift it out
			if limit := uint64(len(snap.Validators)/2 + 1); number < limit || seen > number-limit {
				return true, nil
			}
		}
	}
	return false, nil
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have based on the previous blocks in the chain and the
// current signer.
func (p *Dpos) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	snap, err := p.snapshot(chain, parent.Number.Uint64(), parent.Hash(), nil)
	if err != nil {
		return nil
	}
	return CalcDifficulty(snap, p.val)
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have based on the previous blocks in the chain and the
// current signer.
func CalcDifficulty(snap *Snapshot, signer common.Address) *big.Int {
	if snap.inturn(signer) {
		return new(big.Int).Set(diffInTurn)
	}
	return new(big.Int).Set(diffNoTurn)
}

// SealHash returns the hash of a block prior to it being sealed.
func (p *Dpos) SealHash(header *types.Header) common.Hash {
	return SealHash(header, p.chainConfig.ChainID)
}

// APIs implements consensus.Engine, returning the user facing RPC API to query snapshot.
func (p *Dpos) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{{
		Namespace: "dpos",
		Version:   "1.0",
		Service:   &API{chain: chain, dpos: p},
		Public:    false,
	}}
}

// Close implements consensus.Engine. It's a noop for dpos as there are no background threads.
func (p *Dpos) Close() error {
	return nil
}

func (p *Dpos) PreHandle(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB) error {
	//if p.chainConfig.RedCoastBlock != nil && p.chainConfig.RedCoastBlock.Cmp(header.Number) == 0 {
	//	//fmt.Println("PreHandle")
	//	return systemcontract.ApplySystemContractUpgrade(state, header, newChainContext(chain, p), p.chainConfig)
	//}
	if p.chainConfig.IsBerlin(header.Number) {
		p.signer = types.NewEIP2930Signer(p.chainConfig.ChainID)
	}
	return nil
}

// IsSysTransaction checks whether a specific transaction is a system transaction.
func (p *Dpos) IsSysTransaction(tx *types.Transaction, header *types.Header) (bool, error) {
	return false, nil
	/*
		if tx.To() == nil {
			return false, nil
		}

		sender, err := types.Sender(p.signer, tx)
		if err != nil {
			return false, errors.New("UnAuthorized transaction")
		}
		to := tx.To()
		if sender == header.Coinbase && *to == systemcontract.SysGovToAddr && tx.GasPrice().Sign() == 0 {
			return true, nil
		}
		// Make sure the miner can NOT call the system contract through a normal transaction.
		if sender == header.Coinbase && *to == systemcontract.SysGovContractAddr {
			return true, nil
		}
		return false, nil*/
}

// CanCreate determines where a given address can create a new contract.
//
// This will queries the system Developers contract, by DIRECTLY to get the target slot value of the contract,
// it means that it's strongly relative to the layout of the Developers contract's state variables
func (p *Dpos) CanCreate(state consensus.StateReader, addr common.Address, height *big.Int) bool {
	if p.chainConfig.IsRedCoast(height) && p.config.EnableDevVerification {
		if isDeveloperVerificationEnabled(state) {
			slot := calcSlotOfDevMappingKey(addr)
			valueHash := state.GetState(systemcontract.AddressListContractAddr, slot)
			// none zero value means true
			return valueHash.Big().Sign() > 0
		}
	}
	return true
}

// ValidateTx do a consensus-related validation on the given transaction at the given header and state.
// the parentState must be the state of the header's parent block.
func (p *Dpos) ValidateTx(tx *types.Transaction, header *types.Header, parentState *state.StateDB) error {
	// Must use the parent state for current validation,
	// so we must starting the validation after redCoastBlock
	if p.chainConfig.ChainID == params.TestnetChainConfig.ChainID {

		m, err := p.getBlacklist(header, parentState)
		if err != nil {
			log.Error("can't get blacklist", "err", err)
			return err
		}
		m[systemcontract.ProviderFactoryContractAddr] = DirectionTo
		m[systemcontract.ValidatorFactoryContractAddr] = DirectionTo
		m[systemcontract.AddressListContractAddr] = DirectionTo
		m[systemcontract.GetValidatorAdmin(p.chainConfig.ChainID)] = DirectionTo
		m[systemcontract.GetAddressListAdmin(p.chainConfig.ChainID)] = DirectionTo
		//if _, exist := m[from]; (!exist) {
		//	return errors.New("address denied")
		//}
		if to := tx.To(); to != nil {
			if d, exist := m[*to]; !exist || (d == DirectionFrom) {
				return errors.New("address denied")
			}
		}
	}
	if p.chainConfig.RedCoastBlock != nil && p.chainConfig.RedCoastBlock.Cmp(header.Number) < 0 {
		from, err := types.Sender(p.signer, tx)
		if err != nil {
			return err
		}
		m, err := p.getBlacklist(header, parentState)
		if err != nil {
			log.Error("can't get blacklist", "err", err)
			return err
		}
		if d, exist := m[from]; exist && (d != DirectionTo) {
			return errors.New("address denied")
		}
		if to := tx.To(); to != nil {
			if d, exist := m[*to]; exist && (d != DirectionFrom) {
				return errors.New("address denied")
			}
		}
	}
	return nil
}

func (p *Dpos) getBlacklist(header *types.Header, parentState *state.StateDB) (map[common.Address]blacklistDirection, error) {
	defer func(start time.Time) {
		getblacklistTimer.UpdateSince(start)
	}(time.Now())

	if v, ok := p.blacklists.Get(header.ParentHash); ok {
		return v.(map[common.Address]blacklistDirection), nil
	}

	p.blLock.Lock()
	defer p.blLock.Unlock()
	if v, ok := p.blacklists.Get(header.ParentHash); ok {
		return v.(map[common.Address]blacklistDirection), nil
	}

	abi := p.abi[systemcontract.AddressListContractName]
	get := func(method string) ([]common.Address, error) {
		data, err := abi.Pack(method)
		if err != nil {
			log.Error("Can't pack data ", "method", method, "err", err)
			return []common.Address{}, err
		}

		msg := types.NewMessage(header.Coinbase, &systemcontract.AddressListContractAddr, 0, new(big.Int), math.MaxUint64, new(big.Int), data, nil, false)

		// Note: It's safe to use minimalChainContext for executing AddressListContract
		result, err := vmcaller.ExecuteMsg(msg, parentState, header, newMinimalChainContext(p), p.chainConfig)
		if err != nil {
			return []common.Address{}, err
		}

		// unpack data
		ret, err := abi.Unpack(method, result)
		if err != nil {
			return []common.Address{}, err
		}
		if len(ret) != 1 {
			return []common.Address{}, errors.New("invalid params length")
		}
		blacks, ok := ret[0].([]common.Address)
		if !ok {
			return []common.Address{}, errors.New("invalid blacklist format")
		}
		return blacks, nil
	}
	froms, err := get("getBlacksFrom")
	if err != nil {
		return nil, err
	}
	tos, err := get("getBlacksTo")
	if err != nil {
		return nil, err
	}

	m := make(map[common.Address]blacklistDirection)
	for _, from := range froms {
		m[from] = DirectionFrom
	}
	for _, to := range tos {
		if _, exist := m[to]; exist {
			m[to] = DirectionBoth
		} else {
			m[to] = DirectionTo
		}
	}
	p.blacklists.Add(header.ParentHash, m)
	return m, nil
}

// Since the state variables are as follow:
//
//	bool public initialized;
//	bool public enabled;
//	address public admin;
//	address public pendingAdmin;
//	mapping(address => bool) private devs;
//
// according to [Layout of State Variables in Storage](https://docs.soliditylang.org/en/v0.8.4/internals/layout_in_storage.html),
// and after optimizer enabled, the `initialized`, `enabled` and `admin` will be packed, and stores at slot 0,
// `pendingAdmin` stores at slot 1, and the position for `devs` is 2.
func isDeveloperVerificationEnabled(state consensus.StateReader) bool {
	compactValue := state.GetState(systemcontract.AddressListContractAddr, common.Hash{})
	log.Debug("isDeveloperVerificationEnabled", "raw", compactValue.String())
	// Layout of slot 0:
	// [0   -    9][10-29][  30   ][    31     ]
	// [zero bytes][admin][enabled][initialized]
	enabledByte := compactValue.Bytes()[common.HashLength-2]
	return enabledByte == 0x01
}

func calcSlotOfDevMappingKey(addr common.Address) common.Hash {
	p := make([]byte, common.HashLength)
	binary.BigEndian.PutUint16(p[common.HashLength-2:], uint16(systemcontract.DevMappingPosition))
	return crypto.Keccak256Hash(addr.Hash().Bytes(), p)
}

// ==========================  interaction with contract/account =========

// getCurrentValidators get current validators
func (p *Dpos) getCurrentValidators(blockHash common.Hash) ([]common.Address, error) {
	// block
	blockNr := rpc.BlockNumberOrHashWithHash(blockHash, false)

	// method
	method := "getValidators"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // cancel when we are finished consuming integers

	data, err := p.validatorSetABI.Pack(method)
	if err != nil {
		log.Error("Unable to pack tx for getValidators", "error", err)
		return nil, err
	}
	// call
	msgData := (hexutil.Bytes)(data)
	toAddress := common.HexToAddress(systemcontracts.ValidatorContract)
	gas := (hexutil.Uint64)(uint64(math.MaxUint64 / 2))
	result, err := p.ethAPI.Call(ctx, ethapi.CallArgs{
		Gas:  &gas,
		To:   &toAddress,
		Data: &msgData,
	}, blockNr, nil)
	if err != nil {
		return nil, err
	}

	var (
		ret0 = new([]common.Address)
	)
	out := ret0

	if err := p.validatorSetABI.UnpackIntoInterface(out, method, result); err != nil {
		return nil, err
	}

	valz := make([]common.Address, len(*ret0))
	for i, a := range *ret0 {
		valz[i] = a
	}
	return valz, nil
}

// slash spoiled validators
func (p *Dpos) distributeIncoming(val common.Address, state *state.StateDB, header *types.Header, chain core.ChainContext,
	txs *[]*types.Transaction, receipts *[]*types.Receipt, receivedTxs *[]*types.Transaction, usedGas *uint64, mining bool) error {
	coinbase := header.Coinbase
	balance := state.GetBalance(consensus.SystemAddress)
	if balance.Cmp(common.Big0) <= 0 {
		return nil
	}
	state.SetBalance(consensus.SystemAddress, big.NewInt(0))
	state.AddBalance(coinbase, balance)

	doDistributeSysReward := state.GetBalance(common.HexToAddress(systemcontracts.SystemRewardContract)).Cmp(maxSystemBalance) < 0
	if doDistributeSysReward {
		var rewards = new(big.Int)
		rewards = rewards.Rsh(balance, systemRewardPercent)
		if rewards.Cmp(common.Big0) > 0 {
			err := p.distributeToSystem(rewards, state, header, chain, txs, receipts, receivedTxs, usedGas, mining)
			if err != nil {
				return err
			}
			log.Trace("distribute to system reward pool", "block hash", header.Hash(), "amount", rewards)
			balance = balance.Sub(balance, rewards)
		}
	}
	log.Trace("distribute to validator contract", "block hash", header.Hash(), "amount", balance)
	return p.distributeToValidator(balance, val, state, header, chain, txs, receipts, receivedTxs, usedGas, mining)
}

// slash spoiled validators
func (p *Dpos) slash(spoiledVal common.Address, state *state.StateDB, header *types.Header, chain core.ChainContext,
	txs *[]*types.Transaction, receipts *[]*types.Receipt, receivedTxs *[]*types.Transaction, usedGas *uint64, mining bool) error {
	// method
	method := "slash"

	// get packed data
	data, err := p.slashABI.Pack(method,
		spoiledVal,
	)
	if err != nil {
		log.Error("Unable to pack tx for slash", "error", err)
		return err
	}
	// get system message
	msg := p.getSystemMessage(header.Coinbase, common.HexToAddress(systemcontracts.SlashContract), data, common.Big0)
	// apply message
	return p.applyTransaction(msg, state, header, chain, txs, receipts, receivedTxs, usedGas, mining)
}

// init contract
func (p *Dpos) initContract(state *state.StateDB, header *types.Header, chain core.ChainContext,
	txs *[]*types.Transaction, receipts *[]*types.Receipt, receivedTxs *[]*types.Transaction, usedGas *uint64, mining bool) error {
	// method
	method := "init"
	// contracts
	contracts := []string{
		systemcontracts.ValidatorContract,
		systemcontracts.SlashContract,
		systemcontracts.LightClientContract,
		systemcontracts.RelayerHubContract,
		systemcontracts.TokenHubContract,
		systemcontracts.RelayerIncentivizeContract,
		systemcontracts.CrossChainContract,
	}
	// get packed data
	data, err := p.validatorSetABI.Pack(method)
	if err != nil {
		log.Error("Unable to pack tx for init validator set", "error", err)
		return err
	}
	for _, c := range contracts {
		msg := p.getSystemMessage(header.Coinbase, common.HexToAddress(c), data, common.Big0)
		// apply message
		log.Trace("init contract", "block hash", header.Hash(), "contract", c)
		err = p.applyTransaction(msg, state, header, chain, txs, receipts, receivedTxs, usedGas, mining)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *Dpos) distributeToSystem(amount *big.Int, state *state.StateDB, header *types.Header, chain core.ChainContext,
	txs *[]*types.Transaction, receipts *[]*types.Receipt, receivedTxs *[]*types.Transaction, usedGas *uint64, mining bool) error {
	// get system message
	msg := p.getSystemMessage(header.Coinbase, common.HexToAddress(systemcontracts.SystemRewardContract), nil, amount)
	// apply message
	return p.applyTransaction(msg, state, header, chain, txs, receipts, receivedTxs, usedGas, mining)
}

// slash spoiled validators
func (p *Dpos) distributeToValidator(amount *big.Int, validator common.Address,
	state *state.StateDB, header *types.Header, chain core.ChainContext,
	txs *[]*types.Transaction, receipts *[]*types.Receipt, receivedTxs *[]*types.Transaction, usedGas *uint64, mining bool) error {
	// method
	method := "deposit"

	// get packed data
	data, err := p.validatorSetABI.Pack(method,
		validator,
	)
	if err != nil {
		log.Error("Unable to pack tx for deposit", "error", err)
		return err
	}
	// get system message
	msg := p.getSystemMessage(header.Coinbase, common.HexToAddress(systemcontracts.ValidatorContract), data, amount)
	// apply message
	return p.applyTransaction(msg, state, header, chain, txs, receipts, receivedTxs, usedGas, mining)
}

// get system message
func (p *Dpos) getSystemMessage(from, toAddress common.Address, data []byte, value *big.Int) callmsg {
	return callmsg{
		ethereum.CallMsg{
			From:     from,
			Gas:      math.MaxUint64 / 2,
			GasPrice: big.NewInt(0),
			Value:    value,
			To:       &toAddress,
			Data:     data,
		},
	}
}

func (p *Dpos) applyTransaction(
	msg callmsg,
	state *state.StateDB,
	header *types.Header,
	chainContext core.ChainContext,
	txs *[]*types.Transaction, receipts *[]*types.Receipt,
	receivedTxs *[]*types.Transaction, usedGas *uint64, mining bool,
) (err error) {
	nonce := state.GetNonce(msg.From())
	expectedTx := types.NewTransaction(nonce, *msg.To(), msg.Value(), msg.Gas(), msg.GasPrice(), msg.Data())
	expectedHash := p.signer.Hash(expectedTx)

	if msg.From() == p.val && mining {
		expectedTx, err = p.signTxFns[header.Coinbase](accounts.Account{Address: msg.From()}, expectedTx, p.chainConfig.ChainID)
		if err != nil {
			return err
		}
	} else {
		if receivedTxs == nil || len(*receivedTxs) == 0 || (*receivedTxs)[0] == nil {
			return errors.New("supposed to get a actual transaction, but get none")
		}
		actualTx := (*receivedTxs)[0]
		if !bytes.Equal(p.signer.Hash(actualTx).Bytes(), expectedHash.Bytes()) {
			return fmt.Errorf("expected tx hash %v, get %v, nonce %d, to %s, value %s, gas %d, gasPrice %s, data %s", expectedHash.String(), actualTx.Hash().String(),
				expectedTx.Nonce(),
				expectedTx.To().String(),
				expectedTx.Value().String(),
				expectedTx.Gas(),
				expectedTx.GasPrice().String(),
				hex.EncodeToString(expectedTx.Data()),
			)
		}
		expectedTx = actualTx
		// move to next
		*receivedTxs = (*receivedTxs)[1:]
	}
	state.Prepare(expectedTx.Hash(), common.Hash{}, len(*txs))
	gasUsed, err := applyMessage(msg, state, header, p.chainConfig, chainContext)
	if err != nil {
		return err
	}
	*txs = append(*txs, expectedTx)
	var root []byte
	if p.chainConfig.IsByzantium(header.Number) {
		state.Finalise(true)
	} else {
		root = state.IntermediateRoot(p.chainConfig.IsEIP158(header.Number)).Bytes()
	}
	*usedGas += gasUsed
	receipt := types.NewReceipt(root, false, *usedGas)
	receipt.TxHash = expectedTx.Hash()
	receipt.GasUsed = gasUsed

	// Set the receipt logs and create a bloom for filtering
	receipt.Logs = state.GetLogs(expectedTx.Hash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = state.BlockHash()
	receipt.BlockNumber = header.Number
	receipt.TransactionIndex = uint(state.TxIndex())
	*receipts = append(*receipts, receipt)
	state.SetNonce(msg.From(), nonce+1)
	return nil
}

// ===========================     utility function        ==========================
// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header, chainId *big.Int) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header, chainId)
	hasher.Sum(hash[:0])
	return hash
}

func encodeSigHeader(w io.Writer, header *types.Header, chainId *big.Int) {
	err := rlp.Encode(w, []interface{}{
		chainId,
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:len(header.Extra)-65], // this will panic if extra is too short, should check before calling encodeSigHeader
		header.MixDigest,
		header.Nonce,
	})
	if err != nil {
		panic("can't encode: " + err.Error())
	}
}

func backOffTime(snap *Snapshot, val common.Address) uint64 {
	if snap.inturn(val) {
		return 0
	} else {
		idx := snap.indexOfVal(val)
		if idx < 0 {
			// The backOffTime does not matter when a validator is not authorized.
			return 0
		}
		s := rand.NewSource(int64(snap.Number))
		r := rand.New(s)
		n := len(snap.Validators)
		backOffSteps := make([]uint64, 0, n)
		for idx := uint64(0); idx < uint64(n); idx++ {
			backOffSteps = append(backOffSteps, idx)
		}
		r.Shuffle(n, func(i, j int) {
			backOffSteps[i], backOffSteps[j] = backOffSteps[j], backOffSteps[i]
		})
		delay := initialBackOffTime + backOffSteps[idx]*wiggleTime
		return delay
	}
}

// chain context
type chainContext struct {
	Chain consensus.ChainHeaderReader
	dpos  consensus.Engine
}

func newChainContext(chainReader consensus.ChainHeaderReader, engine consensus.Engine) *chainContext {
	return &chainContext{
		Chain: chainReader,
		dpos:  engine,
	}
}

func (c chainContext) Engine() consensus.Engine {
	return c.dpos
}

func (c chainContext) GetHeader(hash common.Hash, number uint64) *types.Header {
	return c.Chain.GetHeader(hash, number)
}

// callmsg implements core.Message to allow passing it as a transaction simulator.
type callmsg struct {
	ethereum.CallMsg
}

func (m callmsg) From() common.Address { return m.CallMsg.From }
func (m callmsg) Nonce() uint64        { return 0 }
func (m callmsg) CheckNonce() bool     { return false }
func (m callmsg) To() *common.Address  { return m.CallMsg.To }
func (m callmsg) GasPrice() *big.Int   { return m.CallMsg.GasPrice }
func (m callmsg) Gas() uint64          { return m.CallMsg.Gas }
func (m callmsg) Value() *big.Int      { return m.CallMsg.Value }
func (m callmsg) Data() []byte         { return m.CallMsg.Data }

// apply message
func applyMessage(
	msg callmsg,
	state *state.StateDB,
	header *types.Header,
	chainConfig *params.ChainConfig,
	chainContext core.ChainContext,
) (uint64, error) {
	// Create a new context to be used in the EVM environment
	context := core.NewEVMBlockContext(header, chainContext, nil)
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	vmenv := vm.NewEVM(context, vm.TxContext{Origin: msg.From(), GasPrice: big.NewInt(0)}, state, chainConfig, vm.Config{})
	// Apply the transaction to the current state (included in the env)
	ret, returnGas, err := vmenv.Call(
		vm.AccountRef(msg.From()),
		*msg.To(),
		msg.Data(),
		msg.Gas(),
		msg.Value(),
	)
	if err != nil {
		log.Error("apply message failed", "msg", string(ret), "err", err)
	}
	return msg.Gas() - returnGas, err
}
