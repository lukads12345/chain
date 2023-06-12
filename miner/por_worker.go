package miner

import (
	"PureChain/common"
	"PureChain/consensus"
	"PureChain/core"
	"PureChain/log"
	"PureChain/params"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/sha3"
	"io/ioutil"
	"math/big"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	safeBlockNumber        = 5        // safe block number
	oneLoopCount           = 5        // one round hash count
	challengeTreeNodeCount = 50331648 // tree leaf count  for 3 G
)
const (
	NotStart int = iota
	Create
	Success
	Fail
)

type TreeNodeValue *[]byte
type TreeNode struct {
	PtrLeftSon  *TreeNode
	PtrRightSon *TreeNode
	Data        TreeNodeValue
}

type challengeTask struct {
	Seed            uint64
	SeedSignature   string
	Validator       common.Address
	Provider        common.Address
	TaskBlockNumber uint64
	TransactionHash common.Hash
	CreateTxHash    string
}

type challengeResult struct {
	TaskId         int64             `json:"task_id"`
	Success        bool              `json:"success"`
	Paths          map[uint64]string `json:"paths"`
	ChallengeCount int64             `json:"challenge_count"`
}

// ChallengeFinishData is for challenge commit
type ChallengeFinishData struct {
	Seed            uint64
	Provider        common.Address
	challengeAmount uint64
	rootHash        *big.Int
	challengeState  int
	Validator       common.Address
}

type porWorker struct {
	config        *Config
	chainConfig   *params.ChainConfig
	engine        consensus.Engine
	eth           Backend
	chain         *core.BlockChain
	ChallengeChan chan challengeTask
	exitCh        chan struct{}
	FinishCh      *chan ChallengeFinishData
	LockList      sync.Map
}

func (p *porWorker) close() {
	close(p.exitCh)
}

func queryHeart(commitUrl string) string {
	resp, err := http.Get(commitUrl + "/heart")
	if err != nil {
		fmt.Println(err)
		return ""
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	if resp.StatusCode == 200 {
		return string(body)
	}
	return ""
}
func submitSeed(commitUrl string, seed uint64, blockNumber uint64, Validator string, Provider string, CreateTx string, Signature string) string {
	url := commitUrl + "/submit_seed"
	method := "POST"

	payload := strings.NewReader(fmt.Sprintf(`{"seed":%v,"block_number":%v,"validator":"%v","provider":"%v","create_tx":"%v","Signature":"%v"}`, seed, blockNumber, Validator, Provider, CreateTx, Signature))

	client := &http.Client{}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
		return ""
	}
	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	//fmt.Println(string(body))
	return string(body)
}

func legacySum(data []byte) []byte {
	sha := sha3.NewLegacyKeccak256()
	sha.Write(data)
	return sha.Sum(nil)
}
func verifyTree(treePath string) (bool, string) {
	var retData [][]string
	err := json.Unmarshal([]byte(treePath), &retData)
	if err != nil {
		return false, ""
	}
	var hexString string

	for idx, oneData := range retData {
		if idx == len(retData)-1 {
			if strings.Contains(oneData[0], hexString) {
				return true, oneData[0]
			}
			return false, ""
		}
		if (len(oneData)) != 2 {
			return false, ""
		}
		if idx != 0 {
			if !(strings.Contains(oneData[0], hexString)) && !(strings.Contains(oneData[1], hexString)) {
				return false, ""
			}
		}
		sha := sha3.NewLegacyKeccak256()
		tmpByte, err := hex.DecodeString(oneData[0])
		if err != nil {
			return false, ""
		}
		sha.Write(tmpByte)
		tmpByte, err = hex.DecodeString(oneData[1])
		if err != nil {
			return false, ""
		}
		sha.Write(tmpByte)
		hexString = hex.EncodeToString(sha.Sum(nil))
	}
	return false, ""
}

func verifyLeaf(seed, index uint64, treePath string) bool {
	var retData [][]string
	err := json.Unmarshal([]byte(treePath), &retData)
	if err != nil {
		return false
	}
	seedByte := make([]byte, 8)
	binary.LittleEndian.PutUint64(seedByte, seed)
	middle := legacySum(seedByte)
	for i := uint64(0); i <= index; i++ {
		for j := 0; j < oneLoopCount; j++ {
			middle = legacySum(middle[:])
		}
	}
	middleHex := hex.EncodeToString(middle)
	if index%2 == 0 {
		if middleHex == retData[0][0] {
			return true
		}
	} else {
		if middleHex == retData[0][1] {
			return true
		}
	}
	return false
}
func ParentHash(leftNode []byte, rightNode []byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(leftNode)
	hash.Write(rightNode)
	return hash.Sum(nil)
}
func BuildTreeFromRetrievalAddresses(seeds []string) (*TreeNode, error) {
	retrievalDatas := make([][]byte, 0, 0)
	for _, oneRoot := range seeds {
		bytes, _ := hex.DecodeString(oneRoot)
		retrievalDatas = append(retrievalDatas, bytes)
	}

	listNext := make([]*TreeNode, 0)
	if len(retrievalDatas) == 1 {
		lNode := new(TreeNode)
		lNode.PtrLeftSon, lNode.PtrRightSon = nil, nil
		lNode.Data = &retrievalDatas[0]
		return lNode, nil
	}
	// Init listPrev
	for i := 0; i < len(retrievalDatas); i = i + 2 {

		lVal := retrievalDatas[i]
		var rVal []byte
		if (i + 1) == len(retrievalDatas) {
			rVal = retrievalDatas[i]
		} else {
			rVal = retrievalDatas[i+1]
		}
		//rVal := retrievalDatas[i+1]
		lNode := new(TreeNode)
		lNode.PtrLeftSon, lNode.PtrRightSon = nil, nil
		lNode.Data = &lVal

		rNode := new(TreeNode)
		rNode.PtrLeftSon, rNode.PtrRightSon = nil, nil
		rNode.Data = &rVal

		pVal := ParentHash(lVal, rVal)
		pNode := new(TreeNode)
		pNode.PtrLeftSon = lNode
		pNode.PtrRightSon = rNode
		pNode.Data = &pVal

		listNext = append(listNext, pNode)
	}

	for {
		listTemp := listNext
		listNext = make([]*TreeNode, 0)
		if len(listTemp) == 1 {
			return listTemp[0], nil
		}
		for i := 0; i < len(listTemp); i = i + 2 {
			lVal := *listTemp[i].Data
			var rVal []byte
			if (i + 1) == len(listTemp) {
				rVal = *listTemp[i].Data
			} else {
				rVal = *listTemp[i+1].Data
			}

			pVal := ParentHash(lVal, rVal)
			pNode := new(TreeNode)
			pNode.PtrLeftSon = listTemp[i]
			if (i + 1) == len(listTemp) {
				pNode.PtrRightSon = listTemp[i]
			} else {
				pNode.PtrRightSon = listTemp[i+1]
			}
			pNode.Data = &pVal

			listNext = append(listNext, pNode)
		}

	}

}

func verifyTask(seed uint64, index uint64, result challengeResult) *big.Int {
	roots := make([]string, 0, 0)
	for i := uint64(0); i < uint64(len(result.Paths)); i++ {
		path, exist := result.Paths[seed+i]
		if !exist {
			return nil
		}
		success, rootHash := verifyTree(path)
		if !success {
			return nil
		}
		roots = append(roots, rootHash)
		if rand.Intn(100) < 10 {
			success := verifyLeaf(seed+i, index, path)
			if success {
				return nil
			}
		}
	}
	node, err := BuildTreeFromRetrievalAddresses(roots)
	if err != nil {
		return nil
	}
	return new(big.Int).SetBytes(*node.Data)

}

func submitIndex(commitUrl string, index uint64, blockNumber uint64, seed uint64) string {
	url := commitUrl + "/submit_index"
	method := "POST"

	payload := strings.NewReader(fmt.Sprintf(`{"index":%v,"block_number":%v,"seed":%v}`, index, blockNumber, seed))

	client := &http.Client{}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
		return ""
	}
	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	//fmt.Println(string(body))
	return string(body)
}

func NewPorWorker(config *Config, chainConfig *params.ChainConfig, engine consensus.Engine, eth Backend, finishCh *chan ChallengeFinishData) *porWorker {
	porWorker := &porWorker{
		config:        config,
		chainConfig:   chainConfig,
		engine:        engine,
		eth:           eth,
		chain:         eth.BlockChain(),
		ChallengeChan: make(chan challengeTask, 10),
		exitCh:        make(chan struct{}),
		FinishCh:      finishCh,
		LockList:      sync.Map{},
	}
	go porWorker.mainLoop()
	return porWorker
}

func queryReady(commitUrl string, blockNumber uint64, seed uint64) string {
	resp, err := http.Get(commitUrl + "/ready?blockNumber=" + strconv.FormatUint(blockNumber, 10) + "&seed=" + strconv.FormatUint(seed, 10))
	if err != nil {
		fmt.Println(err)
		return ""
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	if resp.StatusCode == 200 {
		return string(body)
	}
	return ""
}

func queryChallengeResult(commitUrl string, blockNumber uint64, seed uint64) string {
	resp, err := http.Get(commitUrl + "/challenge_result?blockNumber=" + strconv.FormatUint(blockNumber, 10) + "&seed=" + strconv.FormatUint(seed, 10))
	if err != nil {
		fmt.Println(err)
		return ""
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	if resp.StatusCode == 200 {
		return string(body)
	}
	return ""
}

func (p *porWorker) challengeMainLoop(challenge challengeTask) {
	defer p.ReleaseLock(challenge.Validator)
	for {
		//wait for block confirm

		if p.chain.CurrentHeader().Number.Uint64()-challenge.TaskBlockNumber > safeBlockNumber &&
			p.chain.CurrentHeader().Number.Uint64() > challenge.TaskBlockNumber {
			blockTemp := p.chain.GetBlockByNumber(challenge.TaskBlockNumber)
			txsReceipt := p.eth.BlockChain().GetReceiptsByHash(blockTemp.Hash())
			if len(txsReceipt) == 0 {
				return
			}
			seedByte := make([]byte, 8)
			binary.LittleEndian.PutUint64(seedByte, challenge.Seed)

			isFound := false
			for _, txReceipt := range txsReceipt {
				if txReceipt.TxHash == challenge.TransactionHash {
					if txReceipt.Status == 1 && len(txReceipt.Logs) > 0 {
						isFound = true
						break
					} else {

						return
					}
				}
			}
			if !isFound {
				return
			} else {
				break
			}

		}
		time.Sleep(time.Second * 10)
	}
	res := submitSeed(p.chain.Config().Dpos.ChallengeCommitUrl, challenge.Seed, challenge.TaskBlockNumber, strings.ToLower(challenge.Validator.Hex()), strings.ToLower(challenge.Provider.Hex()), challenge.TransactionHash.Hex(), challenge.SeedSignature)
	startTime := time.Now()
	state := 0 // 0 wait ready  1 commit challenge index  2 get challenge path verify and cal result
	index := rand.Intn(challengeTreeNodeCount)
	if res != "" {
		for {
			if state == 0 && queryReady(p.chain.Config().Dpos.ChallengeCommitUrl, challenge.TaskBlockNumber, challenge.Seed) == "success" {
				if submitIndex(p.chain.Config().Dpos.ChallengeCommitUrl, uint64(index), challenge.TaskBlockNumber, challenge.Seed) != "" {
					state = 1
					startTime = time.Now()
				}
			}
			if state == 1 {
				res := queryChallengeResult(p.chain.Config().Dpos.ChallengeCommitUrl, challenge.TaskBlockNumber, challenge.Seed)
				if res != "" {
					state = 2
					challengeRes := challengeResult{}
					json.Unmarshal([]byte(res), &challengeRes)
					if challengeRes.Success && int64(len(challengeRes.Paths)) == challengeRes.ChallengeCount {
						//todo cal root hash
						if (time.Now().Sub(startTime)) < 3*time.Minute {
							var rootHash *big.Int
							if challengeRes.ChallengeCount == 0 {
								rootHash = big.NewInt(0)
							} else {
								rootHash = verifyTask(challenge.Seed, uint64(index), challengeRes)
							}
							if rootHash != nil {
								*p.FinishCh <- ChallengeFinishData{challengeState: Success, Seed: challenge.Seed, Provider: challenge.Provider, challengeAmount: uint64(challengeRes.ChallengeCount), rootHash: rootHash, Validator: challenge.Validator}
							} else {

								*p.FinishCh <- ChallengeFinishData{challengeState: Fail, Seed: challenge.Seed, Provider: challenge.Provider, challengeAmount: 0, rootHash: common.Big0, Validator: challenge.Validator}

							}
							break
						} else {
							*p.FinishCh <- ChallengeFinishData{challengeState: Fail, Seed: challenge.Seed, Provider: challenge.Provider, challengeAmount: 0, rootHash: common.Big0, Validator: challenge.Validator}
							break
						}
					}
				}
				if (time.Now().Sub(startTime)) > 3*time.Minute {
					*p.FinishCh <- ChallengeFinishData{challengeState: Fail, Seed: challenge.Seed, Provider: challenge.Provider, challengeAmount: 0, rootHash: common.Big0, Validator: challenge.Validator}
					break
				}

			}

			if (time.Now().Sub(startTime)) > 7*time.Minute {
				// not response

				*p.FinishCh <- ChallengeFinishData{challengeState: Fail, Seed: challenge.Seed, Provider: challenge.Provider, challengeAmount: 0, rootHash: common.Big0, Validator: challenge.Validator}
				break
			}
			time.Sleep(time.Second * 10)
		}
	}
}
func (p *porWorker) AddLock(address common.Address) {
	p.LockList.Store(address, true)

}
func (p *porWorker) ReleaseLock(address common.Address) {
	p.LockList.Store(address, false)

}
func (p *porWorker) CanLock(address common.Address) bool {

	value, ok := p.LockList.Load(address)
	if ok {
		if value.(bool) == true {
			return false
		}
	}

	return true

}
func (p *porWorker) mainLoop() {
	if queryHeart(p.chain.Config().Dpos.ChallengeCommitUrl) == "" {
		log.Error("commit url not live,please check url!", "url", p.chain.Config().Dpos.ChallengeCommitUrl)
		p.chain.Config().Dpos.Por = false
		return
	}
	for {
		select {
		case challenge := <-p.ChallengeChan:
			go p.challengeMainLoop(challenge)

		case <-p.exitCh:
			return
		}
	}
}
