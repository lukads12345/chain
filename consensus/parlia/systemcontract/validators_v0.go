package systemcontract

import (
	"PureChain/accounts/abi"
	"PureChain/common"
	"PureChain/consensus/parlia/vmcaller"
	"PureChain/core"
	"PureChain/core/state"
	"PureChain/core/types"
	"PureChain/log"
	"PureChain/params"
	"bytes"
	"errors"
	"math"
	"math/big"
	"sort"
)

type ValidatorV0 struct {
	abi          abi.ABI
	contractAddr common.Address
}

func NewValidatorV0() *ValidatorV0 {
	return &ValidatorV0{
		abi:          abiMap[ValidatorsContractName],
		contractAddr: ValidatorsContractAddr,
	}
}

func (v *ValidatorV0) GetTopValidators(statedb *state.StateDB, header *types.Header, chainContext core.ChainContext, config *params.ChainConfig) ([]common.Address, error) {
	method := "getTopValidators"
	data, err := v.abi.Pack(method)
	if err != nil {
		log.Error("Can't pack data for getTopValidators", "error", err)
		return []common.Address{}, err
	}

	msg := types.NewMessage(header.Coinbase, &v.contractAddr, 0, new(big.Int), math.MaxUint64, new(big.Int), data, nil, false)
	//fmt.Println(msg)
	result, err := vmcaller.ExecuteMsg(msg, statedb, header, chainContext, config)
	if err != nil {
		return []common.Address{}, err
	}
	//fmt.Println("result",result)
	// unpack data
	ret, err := v.abi.Unpack(method, result)
	if err != nil {
		return []common.Address{}, err
	}
	if len(ret) != 1 {
		return []common.Address{}, errors.New("invalid params length")
	}
	validators, ok := ret[0].([]common.Address)
	if !ok {
		return []common.Address{}, errors.New("invalid validators format")
	}
	sort.Slice(validators, func(i, j int) bool {
		return bytes.Compare(validators[i][:], validators[j][:]) < 0
	})
	return validators, err
}

func (v *ValidatorV0) GetValidatorFeeAddr(val common.Address, statedb *state.StateDB, header *types.Header, chainContext core.ChainContext, config *params.ChainConfig) (common.Address, error) {
	method := "getValidatorInfo"
	data, err := v.abi.Pack(method, val)
	if err != nil {
		log.Error("Can't pack data for GetValidatorInfo", "error", err)
		return common.Address{}, err
	}
	msg := types.NewMessage(header.Coinbase, &v.contractAddr, 0, new(big.Int), math.MaxUint64, new(big.Int), data, nil, false)

	// use parent
	result, err := vmcaller.ExecuteMsg(msg, statedb, header, chainContext, config)
	if err != nil {
		return common.Address{}, err
	}
	// unpack data
	ret, err := v.abi.Unpack(method, result)
	if err != nil {
		return common.Address{}, err
	}
	feeAddr, ok := ret[0].(common.Address)
	if !ok {
		return common.Address{}, errors.New("invalid output")
	}
	return feeAddr, nil
}
