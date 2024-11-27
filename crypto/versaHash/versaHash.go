package versaHash

import (
	"crypto/sha256"
	"math/big"
)

func VersaHash(data []byte, nonce []byte, extraNonce []byte) []byte {
	newData := data
	newData = append(newData, byte(len(nonce)+len(extraNonce)))
	newData = append(newData, nonce...)
	newData = append(newData, extraNonce...)

	firsthash := sha256.Sum256(newData)

	keyHash := sha256.Sum256(firsthash[:])

	key := big.NewInt(0).SetBytes(keyHash[:])
	signDataHash := sha256.Sum256(keyHash[:])
	signRet, err := Sign(key, signDataHash)
	if err != nil {
		return make([]byte, 0)
	}
	endHash := sha256.Sum256(signRet[:])
	reverseData := [len(endHash)]byte{}
	for i := 0; i < len(endHash); i++ {
		reverseData[i] = endHash[len(endHash)-1-i]
	}
	return reverseData[:]
}
