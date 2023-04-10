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

const SysGovInteractiveABI = `
[
    {
		"inputs": [
			{
				"internalType": "uint256",
				"name": "id",
				"type": "uint256"
			}
		],
		"name": "finishProposalById",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint32",
				"name": "index",
				"type": "uint32"
			}
		],
		"name": "getPassedProposalByIndex",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "id",
				"type": "uint256"
			},
			{
        		"internalType": "uint256",
        		"name": "action",
        		"type": "uint256"
        	},
			{
				"internalType": "address",
				"name": "from",
				"type": "address"
			},
			{
				"internalType": "address",
				"name": "to",
				"type": "address"
			},
			{
				"internalType": "uint256",
				"name": "value",
				"type": "uint256"
			},
			{
				"internalType": "bytes",
				"name": "data",
				"type": "bytes"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "getPassedProposalCount",
		"outputs": [
			{
				"internalType": "uint32",
				"name": "",
				"type": "uint32"
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
	}
]`

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

const DposFactoryInteractiveABI = `[
    {
        "inputs": [
            {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
            }
        ],
        "name": "getActiveValidators",
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
        "name": "distributeBlockReward",
        "outputs": [],
        "stateMutability": "payable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getTopValidators",
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
                "internalType": "address[]",
                "name": "_candidates",
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
        "inputs": [
            {
                "internalType": "address[]",
                "name": "newSet",
                "type": "address[]"
            },
            {
                "internalType": "uint256",
                "name": "epoch",
                "type": "uint256"
            }
        ],
        "name": "updateActiveValidatorSet",
        "outputs": [],
        "stateMutability": "nonpayable",
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
      "inputs": [],
      "name": "providerFactory",
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
      "inputs": [
        {
          "internalType": "address",
          "name": "_provider_factory",
          "type": "address"
        }
      ],
      "name": "setProviderFactory",
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
      "inputs": [
        {
          "internalType": "address",
          "name": "_admin",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "_order_factory",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "_auditor_factory",
          "type": "address"
        }
      ],
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
      "name": "MIN_VALUE_TO_BE_PROVIDER",
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
          "name": "storage_amount",
          "type": "uint256"
        }
      ],
      "name": "clacProviderAmount",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "pure",
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
      "inputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "name": "provider_pledge",
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
      "name": "reOpenProvider",
      "outputs": [],
      "stateMutability": "payable",
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
    }
  ]
 `

// DevMappingPosition is the position of the state variable `devs`.
// Since the state variables are as follow:
//    bool public initialized;
//    bool public enabled;
//    address public admin;
//    address public pendingAdmin;
//    mapping(address => bool) private devs;
//
// according to [Layout of State Variables in Storage](https://docs.soliditylang.org/en/v0.8.4/internals/layout_in_storage.html),
// and after optimizer enabled, the `initialized`, `enabled` and `admin` will be packed, and stores at slot 0,
// `pendingAdmin` stores at slot 1, so the position for `devs` is 2.
const DevMappingPosition = 2

var (
	/*
		FactoryAdminAddr        = common.HexToAddress("0xce930537a2148B8DC43899ff2E9BcBEE0e801c54")
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
	ValidatorFactoryAdminAddr    = common.HexToAddress("0xce930537a2148B8DC43899ff2E9BcBEE0e801c54")
	AddressListContractName      = "address_list"
	AddressListContractAddr      = common.HexToAddress("0x000000000000000000000000000000000000c001")
	ValidatorFactoryContractName = "validator_factory"
	ValidatorFactoryContractAddr = common.HexToAddress("0x000000000000000000000000000000000000c002")
	abiMap                       map[string]abi.ABI
	ProviderFactoryContractName  = "provider_factory"
)

func init() {
	abiMap = make(map[string]abi.ABI, 0)
	tmpABI, err := abi.JSON(strings.NewReader(ValidatorFactoryABI))
	if err != nil {
		fmt.Println("ccccccccccccccc", err.Error())
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
