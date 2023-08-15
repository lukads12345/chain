package systemcontract

import (
	"PureChain/accounts/abi"
	"PureChain/common"
	"PureChain/params"
	"fmt"
	"math/big"
	"strings"
)

// ValidatorsInteractiveABI contains all methods to interactive with validator contracts.

const PunishInteractiveABI = `
[
	{
		"inputs": [],
		"name": "initialize",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
		  {
			"internalType": "address",
			"name": "val",
			"type": "address"
		  }
		],
		"name": "punish",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
		  {
			"internalType": "uint256",
			"name": "epoch",
			"type": "uint256"
		  }
		],
		"name": "decreaseMissedBlocksCounter",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	  }
]
`

const AddrListInteractiveABI = `
[
    {
        "inputs": [],
        "name": "devVerifyEnabled",
        "outputs": [
            {
                "internalType": "bool",
                "name": "",
                "type": "bool"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getBlacksFrom",
        "outputs": [
            {
                "internalType": "address[]",
                "name": "",
                "type": "address[]"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getBlacksTo",
        "outputs": [
            {
                "internalType": "address[]",
                "name": "",
                "type": "address[]"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "address",
                "name": "_admin",
                "type": "address"
            }
        ],
        "name": "initialize",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "address",
                "name": "addr",
                "type": "address"
            }
        ],
        "name": "isDeveloper",
        "outputs": [
            {
                "internalType": "bool",
                "name": "",
                "type": "bool"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }
]`

const PunishV1InteractiveABI = `[
   {
     "inputs": [],
     "name": "initialize",
     "outputs": [],
     "stateMutability": "nonpayable",
     "type": "function"
   }
]`

const ValidatorFactoryABI = `[
    {
      "inputs": [],
      "stateMutability": "nonpayable",
      "type": "constructor"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "address",
          "name": "",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "name": "ChallengeCreate",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "name": "ChallengeEnd",
      "type": "event"
    },
    {
      "inputs": [],
      "name": "MarginCalls",
      "outputs": [],
      "stateMutability": "payable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "admin_address",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "all_percent",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "name": "all_validators",
      "outputs": [
        {
          "internalType": "contract IValidator",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "provider",
          "type": "address"
        },
        {
          "internalType": "uint256",
          "name": "seed",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "challenge_amount",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "root_hash",
          "type": "uint256"
        },
        {
          "internalType": "enum ValidatorFactory.ChallengeState",
          "name": "_state",
          "type": "uint8"
        }
      ],
      "name": "challengeFinish",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "provider",
          "type": "address"
        },
        {
          "internalType": "uint256",
          "name": "md5_seed",
          "type": "uint256"
        },
        {
          "internalType": "string",
          "name": "url",
          "type": "string"
        }
      ],
      "name": "challengeProvider",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "challenge_all_percent",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "challenge_sdl_trx_id",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "_new_admin",
          "type": "address"
        }
      ],
      "name": "changeAdminAddress",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_new_trx_id",
          "type": "uint256"
        }
      ],
      "name": "changeChallengeSdlTrxID",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_max_challenge_percent",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "_challenge_all_percent",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "_max_challenge_time",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "_max_provider_start_challenge_time",
          "type": "uint256"
        }
      ],
      "name": "changeMaxChallengeParam",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_max_validator_count",
          "type": "uint256"
        }
      ],
      "name": "changeMaxValidatorCount",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "_punish_address",
          "type": "address"
        }
      ],
      "name": "changePunishAddress",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_new_punish_percent",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "_new_punish_all_percent",
          "type": "uint256"
        }
      ],
      "name": "changePunishPercent",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_team_percent",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "_validator_percent",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "_all_percent",
          "type": "uint256"
        }
      ],
      "name": "changeRewardPercent",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "_team_address",
          "type": "address"
        }
      ],
      "name": "changeTeamAddress",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_new_lock",
          "type": "uint256"
        }
      ],
      "name": "changeValidatorLockTime",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_validator_min_pledgeAmount",
          "type": "uint256"
        }
      ],
      "name": "changeValidatorMinPledgeAmount",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_new_interval",
          "type": "uint256"
        }
      ],
      "name": "changeValidatorPunishInterval",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_new_start_limit",
          "type": "uint256"
        }
      ],
      "name": "changeValidatorPunishStartTime",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "validator",
          "type": "address"
        },
        {
          "internalType": "enum ValidatorState",
          "name": "_state",
          "type": "uint8"
        }
      ],
      "name": "changeValidatorState",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "createValidator",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "payable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "current_challenge_provider_count",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "current_validator_count",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "exitProduceBlock",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "getAllActiveValidator",
      "outputs": [
        {
          "components": [
            {
              "internalType": "address",
              "name": "validator",
              "type": "address"
            },
            {
              "internalType": "address",
              "name": "validator_contract",
              "type": "address"
            },
            {
              "internalType": "enum ValidatorState",
              "name": "state",
              "type": "uint8"
            },
            {
              "internalType": "uint256",
              "name": "start_time",
              "type": "uint256"
            }
          ],
          "internalType": "struct ValidatorFactory.ValidatorInfo[]",
          "name": "",
          "type": "tuple[]"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "getAllActiveValidatorAddr",
      "outputs": [
        {
          "internalType": "address[]",
          "name": "",
          "type": "address[]"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "getAllPunishValidator",
      "outputs": [
        {
          "internalType": "address[]",
          "name": "",
          "type": "address[]"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "getAllValidator",
      "outputs": [
        {
          "components": [
            {
              "internalType": "address",
              "name": "validator",
              "type": "address"
            },
            {
              "internalType": "address",
              "name": "validator_contract",
              "type": "address"
            },
            {
              "internalType": "enum ValidatorState",
              "name": "state",
              "type": "uint8"
            },
            {
              "internalType": "uint256",
              "name": "start_time",
              "type": "uint256"
            }
          ],
          "internalType": "struct ValidatorFactory.ValidatorInfo[]",
          "name": "",
          "type": "tuple[]"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "getAllValidatorLength",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "provider_owner",
          "type": "address"
        }
      ],
      "name": "getProviderChallengeInfo",
      "outputs": [
        {
          "components": [
            {
              "internalType": "address",
              "name": "provider",
              "type": "address"
            },
            {
              "internalType": "address",
              "name": "challenge_validator",
              "type": "address"
            },
            {
              "internalType": "uint256",
              "name": "md5_seed",
              "type": "uint256"
            },
            {
              "internalType": "string",
              "name": "url",
              "type": "string"
            },
            {
              "internalType": "uint256",
              "name": "create_challenge_time",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "challenge_finish_time",
              "type": "uint256"
            },
            {
              "internalType": "enum ValidatorFactory.ChallengeState",
              "name": "state",
              "type": "uint8"
            },
            {
              "internalType": "uint256",
              "name": "challenge_amount",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "seed",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "root_hash",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "index",
              "type": "uint256"
            }
          ],
          "internalType": "struct ValidatorFactory.providerChallengeInfo",
          "name": "",
          "type": "tuple"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "getPunishAmount",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address[]",
          "name": "_init_validator",
          "type": "address[]"
        },
        {
          "internalType": "address",
          "name": "_admin",
          "type": "address"
        }
      ],
      "name": "initialize",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "initialized",
      "outputs": [
        {
          "internalType": "bool",
          "name": "",
          "type": "bool"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "max_challenge_percent",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "max_challenge_time",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "max_provider_start_challenge_time",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "max_validator_count",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "name": "owner_validator",
      "outputs": [
        {
          "internalType": "contract IValidator",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        },
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "name": "provider_challenge_info",
      "outputs": [
        {
          "internalType": "address",
          "name": "provider",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "challenge_validator",
          "type": "address"
        },
        {
          "internalType": "uint256",
          "name": "md5_seed",
          "type": "uint256"
        },
        {
          "internalType": "string",
          "name": "url",
          "type": "string"
        },
        {
          "internalType": "uint256",
          "name": "create_challenge_time",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "challenge_finish_time",
          "type": "uint256"
        },
        {
          "internalType": "enum ValidatorFactory.ChallengeState",
          "name": "state",
          "type": "uint8"
        },
        {
          "internalType": "uint256",
          "name": "challenge_amount",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "seed",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "root_hash",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "index",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "provider_factory",
      "outputs": [
        {
          "internalType": "contract IProviderFactory",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "name": "provider_index",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "name": "provider_last_challenge_state",
      "outputs": [
        {
          "internalType": "enum ValidatorFactory.ChallengeState",
          "name": "",
          "type": "uint8"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "punish_address",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "punish_all_percent",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "punish_percent",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "removeRankingList",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "team_address",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "team_percent",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "val",
          "type": "address"
        }
      ],
      "name": "tryPunish",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "provider",
          "type": "address"
        }
      ],
      "name": "validatorNotSubmitResult",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "validator_lock_time",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "validator_percent",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "validator_pledgeAmount",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "validator_punish_interval",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "validator_punish_start_limit",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "name": "whiteList_validator",
      "outputs": [
        {
          "internalType": "contract IValidator",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    }
  ]`

var ProviderFactoryABI = `[
    {
      "inputs": [],
      "stateMutability": "nonpayable",
      "type": "constructor"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "name": "ProviderCreate",
      "type": "event"
    },
    {
      "inputs": [],
      "name": "addMargin",
      "outputs": [],
      "stateMutability": "payable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "admin",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "auditor_factory",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "cpu_count",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "memory_count",
          "type": "uint256"
        }
      ],
      "name": "calcProviderAmount",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "new_admin",
          "type": "address"
        }
      ],
      "name": "changeAdmin",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "new_audit_factory",
          "type": "address"
        }
      ],
      "name": "changeAuditorFactory",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "new_cpu_decimal",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "new_memory_decimal",
          "type": "uint256"
        }
      ],
      "name": "changeDecimal",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "new_order_factory",
          "type": "address"
        }
      ],
      "name": "changeOrderFactory",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_new_min",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "_new_max",
          "type": "uint256"
        }
      ],
      "name": "changeProviderLimit",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_lock_time",
          "type": "uint256"
        }
      ],
      "name": "changeProviderLockTime",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "cpu_count",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "mem_count",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "storage_count",
          "type": "uint256"
        },
        {
          "internalType": "bool",
          "name": "add",
          "type": "bool"
        }
      ],
      "name": "changeProviderResource",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "provider_owner",
          "type": "address"
        },
        {
          "internalType": "bool",
          "name": "whether_start",
          "type": "bool"
        }
      ],
      "name": "changeProviderState",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "cpu_count",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "mem_count",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "storage_count",
          "type": "uint256"
        },
        {
          "internalType": "bool",
          "name": "add",
          "type": "bool"
        }
      ],
      "name": "changeProviderUsedResource",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "_punish_address",
          "type": "address"
        }
      ],
      "name": "changePunishAddress",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_new_punish_start_limit",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "_new_punish_interval",
          "type": "uint256"
        }
      ],
      "name": "changePunishParam",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_new_punish_percent",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "_new_punish_all_percent",
          "type": "uint256"
        }
      ],
      "name": "changePunishPercent",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "closeProvider",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "account",
          "type": "address"
        },
        {
          "internalType": "uint256",
          "name": "cpu_count",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "mem_count",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "storage_count",
          "type": "uint256"
        }
      ],
      "name": "consumeResource",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "cpu_count",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "mem_count",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "storage_count",
          "type": "uint256"
        },
        {
          "internalType": "string",
          "name": "region",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "provider_info",
          "type": "string"
        }
      ],
      "name": "createNewProvider",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "payable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "decimal_cpu",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "decimal_memory",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "account",
          "type": "address"
        }
      ],
      "name": "getProvideContract",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "account",
          "type": "address"
        }
      ],
      "name": "getProvideResource",
      "outputs": [
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "cpu_count",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "memory_count",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "storage_count",
              "type": "uint256"
            }
          ],
          "internalType": "struct poaResource",
          "name": "",
          "type": "tuple"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "account",
          "type": "address"
        }
      ],
      "name": "getProvideTotalResource",
      "outputs": [
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "cpu_count",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "memory_count",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "storage_count",
              "type": "uint256"
            }
          ],
          "internalType": "struct poaResource",
          "name": "",
          "type": "tuple"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "start",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "limit",
          "type": "uint256"
        }
      ],
      "name": "getProviderInfo",
      "outputs": [
        {
          "components": [
            {
              "internalType": "address",
              "name": "provider_contract",
              "type": "address"
            },
            {
              "components": [
                {
                  "components": [
                    {
                      "internalType": "uint256",
                      "name": "cpu_count",
                      "type": "uint256"
                    },
                    {
                      "internalType": "uint256",
                      "name": "memory_count",
                      "type": "uint256"
                    },
                    {
                      "internalType": "uint256",
                      "name": "storage_count",
                      "type": "uint256"
                    }
                  ],
                  "internalType": "struct poaResource",
                  "name": "total",
                  "type": "tuple"
                },
                {
                  "components": [
                    {
                      "internalType": "uint256",
                      "name": "cpu_count",
                      "type": "uint256"
                    },
                    {
                      "internalType": "uint256",
                      "name": "memory_count",
                      "type": "uint256"
                    },
                    {
                      "internalType": "uint256",
                      "name": "storage_count",
                      "type": "uint256"
                    }
                  ],
                  "internalType": "struct poaResource",
                  "name": "used",
                  "type": "tuple"
                },
                {
                  "components": [
                    {
                      "internalType": "uint256",
                      "name": "cpu_count",
                      "type": "uint256"
                    },
                    {
                      "internalType": "uint256",
                      "name": "memory_count",
                      "type": "uint256"
                    },
                    {
                      "internalType": "uint256",
                      "name": "storage_count",
                      "type": "uint256"
                    }
                  ],
                  "internalType": "struct poaResource",
                  "name": "lock",
                  "type": "tuple"
                },
                {
                  "internalType": "bool",
                  "name": "challenge",
                  "type": "bool"
                },
                {
                  "internalType": "enum ProviderState",
                  "name": "state",
                  "type": "uint8"
                },
                {
                  "internalType": "address",
                  "name": "owner",
                  "type": "address"
                },
                {
                  "internalType": "string",
                  "name": "region",
                  "type": "string"
                },
                {
                  "internalType": "string",
                  "name": "info",
                  "type": "string"
                },
                {
                  "internalType": "uint256",
                  "name": "last_challenge_time",
                  "type": "uint256"
                },
                {
                  "internalType": "uint256",
                  "name": "last_margin_time",
                  "type": "uint256"
                }
              ],
              "internalType": "struct providerInfo",
              "name": "info",
              "type": "tuple"
            },
            {
              "internalType": "uint256",
              "name": "margin_amount",
              "type": "uint256"
            },
            {
              "internalType": "address[]",
              "name": "audits",
              "type": "address[]"
            }
          ],
          "internalType": "struct ProviderFactory.providerInfos[]",
          "name": "",
          "type": "tuple[]"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "getProviderInfoLength",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "_provider_contract",
          "type": "address"
        }
      ],
      "name": "getProviderSingle",
      "outputs": [
        {
          "components": [
            {
              "internalType": "address",
              "name": "provider_contract",
              "type": "address"
            },
            {
              "components": [
                {
                  "components": [
                    {
                      "internalType": "uint256",
                      "name": "cpu_count",
                      "type": "uint256"
                    },
                    {
                      "internalType": "uint256",
                      "name": "memory_count",
                      "type": "uint256"
                    },
                    {
                      "internalType": "uint256",
                      "name": "storage_count",
                      "type": "uint256"
                    }
                  ],
                  "internalType": "struct poaResource",
                  "name": "total",
                  "type": "tuple"
                },
                {
                  "components": [
                    {
                      "internalType": "uint256",
                      "name": "cpu_count",
                      "type": "uint256"
                    },
                    {
                      "internalType": "uint256",
                      "name": "memory_count",
                      "type": "uint256"
                    },
                    {
                      "internalType": "uint256",
                      "name": "storage_count",
                      "type": "uint256"
                    }
                  ],
                  "internalType": "struct poaResource",
                  "name": "used",
                  "type": "tuple"
                },
                {
                  "components": [
                    {
                      "internalType": "uint256",
                      "name": "cpu_count",
                      "type": "uint256"
                    },
                    {
                      "internalType": "uint256",
                      "name": "memory_count",
                      "type": "uint256"
                    },
                    {
                      "internalType": "uint256",
                      "name": "storage_count",
                      "type": "uint256"
                    }
                  ],
                  "internalType": "struct poaResource",
                  "name": "lock",
                  "type": "tuple"
                },
                {
                  "internalType": "bool",
                  "name": "challenge",
                  "type": "bool"
                },
                {
                  "internalType": "enum ProviderState",
                  "name": "state",
                  "type": "uint8"
                },
                {
                  "internalType": "address",
                  "name": "owner",
                  "type": "address"
                },
                {
                  "internalType": "string",
                  "name": "region",
                  "type": "string"
                },
                {
                  "internalType": "string",
                  "name": "info",
                  "type": "string"
                },
                {
                  "internalType": "uint256",
                  "name": "last_challenge_time",
                  "type": "uint256"
                },
                {
                  "internalType": "uint256",
                  "name": "last_margin_time",
                  "type": "uint256"
                }
              ],
              "internalType": "struct providerInfo",
              "name": "info",
              "type": "tuple"
            },
            {
              "internalType": "uint256",
              "name": "margin_amount",
              "type": "uint256"
            },
            {
              "internalType": "address[]",
              "name": "audits",
              "type": "address[]"
            }
          ],
          "internalType": "struct ProviderFactory.providerInfos",
          "name": "",
          "type": "tuple"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "punish_amount",
          "type": "uint256"
        }
      ],
      "name": "getPunishAmount",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "getTotalDetail",
      "outputs": [
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "cpu_count",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "memory_count",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "storage_count",
              "type": "uint256"
            }
          ],
          "internalType": "struct poaResource",
          "name": "",
          "type": "tuple"
        },
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "cpu_count",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "memory_count",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "storage_count",
              "type": "uint256"
            }
          ],
          "internalType": "struct poaResource",
          "name": "",
          "type": "tuple"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "_admin",
          "type": "address"
        }
      ],
      "name": "initialize",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "initialized",
      "outputs": [
        {
          "internalType": "bool",
          "name": "",
          "type": "bool"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "max_value_tobe_provider",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "min_value_tobe_provider",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "order_factory",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "provider_lock_time",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "name": "providers",
      "outputs": [
        {
          "internalType": "contract IProvider",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "punish_address",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "punish_all_percent",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "punish_interval",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "punish_percent",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "punish_start_limit",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "account",
          "type": "address"
        },
        {
          "internalType": "uint256",
          "name": "cpu_count",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "mem_count",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "storage_count",
          "type": "uint256"
        }
      ],
      "name": "recoverResource",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "provider",
          "type": "address"
        }
      ],
      "name": "removePunishList",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "total_all",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "cpu_count",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "memory_count",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "storage_count",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "total_used",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "cpu_count",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "memory_count",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "storage_count",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "new_provider",
          "type": "address"
        }
      ],
      "name": "tryPunish",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "val_factory",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "provider_owner",
          "type": "address"
        }
      ],
      "name": "whetherCanPOR",
      "outputs": [
        {
          "internalType": "bool",
          "name": "",
          "type": "bool"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "withdrawMargin",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    }
  ]`

// DevMappingPosition is the position of the state variable `devs`.
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
// `pendingAdmin` stores at slot 1, so the position for `devs` is 2.
const DevMappingPosition = 2

var (
	/*
		FactoryAdminAddr        = common.HexToAddress("0x7a0BbA5EEbD9B84F46A39A9ffd488b8afB88979d")
		SysGovContractName      = "governance"
		AddressListContractName = "address_list"
		DposFactoryContractName = "dpos_factory"
		PunishV1ContractName    = "punish_v1"
		SysGovContractAddr      = common.HexToAddress("0x000000000000000000000000000000000000c000")
		AddressListContractAddr = common.HexToAddress("0x000000000000000000000000000000000000c001")
		DposFactoryContractAddr = common.HexToAddress("0x000000000000000000000000000000000000c002")
		PunishV1ContractAddr    = common.HexToAddress("0x000000000000000000000000000000000000c003")
		// SysGovToAddr is the To address for the system governance transaction, NOT contract address
		SysGovToAddr = common.HexToAddress("0x000000000000000000000000000000000000cccc")
	*/
	ValidatorFactoryAdminAddr     = common.HexToAddress("0x2b9ac060e7d20cf91bbb6719178d957f9c441235")
	ValidatorFactoryTestAdminAddr = common.HexToAddress("0x2b9ac060e7d20cf91bbb6719178d957f9c441235")
	ValidatorFactoryDevAdminAddr  = common.HexToAddress("0x2b9ac060e7d20cf91bbb6719178d957f9c441235")

	AddressListContractName = "address_list"
	AddressListContractAddr = common.HexToAddress("0x000000000000000000000000000000000000c001")

	AddressListContractAdminAddr     = common.HexToAddress("0x2b9ac060e7d20cf91bbb6719178d957f9c441235")
	AddressListTestContractAdminAddr = common.HexToAddress("0x2b9ac060e7d20cf91bbb6719178d957f9c441235")
	AddressListDevContractAdminAddr  = common.HexToAddress("0x2b9ac060e7d20cf91bbb6719178d957f9c441235")

	ValidatorFactoryContractName   = "validator_factory"
	ValidatorFactoryContractAddr   = common.HexToAddress("0x000000000000000000000000000000000000c002")
	ProviderFactoryContractName    = "provider_factory"
	ProviderFactoryContractAddr    = common.HexToAddress("0x000000000000000000000000000000000000C003")
	ValidatorFactoryPunishItemAddr = common.HexToAddress("0x000000000000000000000000000000000000c004")
	ProviderFactoryPunishItemAddr  = common.HexToAddress("0x000000000000000000000000000000000000C005")
	abiMap                         map[string]abi.ABI
)

func init() {
	abiMap = make(map[string]abi.ABI, 0)
	tmpABI, err := abi.JSON(strings.NewReader(ValidatorFactoryABI))
	if err != nil {
		fmt.Println("init error", err.Error())
	}
	abiMap[ValidatorFactoryContractName] = tmpABI
	tmpABI, _ = abi.JSON(strings.NewReader(AddrListInteractiveABI))
	abiMap[AddressListContractName] = tmpABI
	tmpABI, _ = abi.JSON(strings.NewReader(ProviderFactoryABI))
	abiMap[ProviderFactoryContractName] = tmpABI

	/*
		tmpABI, _ := abi.JSON(strings.NewReader(DposFactoryInteractiveABI))
		abiMap[DposFactoryContractName] = tmpABI
		tmpABI, _ = abi.JSON(strings.NewReader(PunishInteractiveABI))
		abiMap[PunishV1ContractName] = tmpABI
		tmpABI, _ = abi.JSON(strings.NewReader(SysGovInteractiveABI))
		abiMap[SysGovContractName] = tmpABI
		tmpABI, _ = abi.JSON(strings.NewReader(AddrListInteractiveABI))
		abiMap[AddressListContractName] = tmpABI*/
}

func GetInteractiveABI() map[string]abi.ABI {

	return abiMap
}
func GetValidatorAdmin(chainId *big.Int) common.Address {
	if chainId.Cmp(params.MainnetChainConfig.ChainID) == 0 {
		return ValidatorFactoryAdminAddr
	} else if chainId.Cmp(params.TestnetChainConfig.ChainID) == 0 {
		return ValidatorFactoryTestAdminAddr
	} else if chainId.Cmp(params.DevnetChainConfig.ChainID) == 0 {
		return ValidatorFactoryDevAdminAddr
	} else {
		return ValidatorFactoryAdminAddr
	}
}
func GetAddressListAdmin(chainId *big.Int) common.Address {
	if chainId.Cmp(params.MainnetChainConfig.ChainID) == 0 {
		return AddressListContractAdminAddr
	} else if chainId.Cmp(params.TestnetChainConfig.ChainID) == 0 {
		return AddressListTestContractAdminAddr
	} else if chainId.Cmp(params.DevnetChainConfig.ChainID) == 0 {
		return AddressListDevContractAdminAddr
	} else {
		return AddressListContractAdminAddr
	}
}
func GetValidatorAddr(blockNum *big.Int, config *params.ChainConfig) *common.Address {
	if config.IsRedCoast(blockNum) {
		return &ValidatorFactoryContractAddr
	}
	return &ValidatorFactoryContractAddr
}

func GetPunishAddr(blockNum *big.Int, config *params.ChainConfig) *common.Address {
	if config.IsRedCoast(blockNum) {
		return &ValidatorFactoryContractAddr
	}
	return &ValidatorFactoryContractAddr
}
