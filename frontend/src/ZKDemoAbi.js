const abi = {
  "_format": "hh-sol-artifact-1",
  "contractName": "ZKDemo",
  "sourceName": "contracts/ZKDemo.sol",
  "abi": [
    {
      "inputs": [
        {
          "internalType": "contract MergeVerifier",
          "name": "_mv",
          "type": "address"
        },
        {
          "internalType": "contract SplitVerifier",
          "name": "_sv",
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
          "indexed": true,
          "internalType": "uint256",
          "name": "noteId",
          "type": "uint256"
        }
      ],
      "name": "CreateNote",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "uint256",
          "name": "nullifierId",
          "type": "uint256"
        }
      ],
      "name": "UseNullifier",
      "type": "event"
    },
    {
      "inputs": [],
      "name": "N_MERGE",
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
      "name": "N_MIX",
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
      "name": "N_SPLIT",
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
          "name": "noteId",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "enc_amt",
          "type": "uint256"
        }
      ],
      "name": "createNote",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "num",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "i",
          "type": "uint256"
        }
      ],
      "name": "getNthUint32",
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
      "inputs": [
        {
          "components": [
            {
              "components": [
                {
                  "internalType": "uint256",
                  "name": "X",
                  "type": "uint256"
                },
                {
                  "internalType": "uint256",
                  "name": "Y",
                  "type": "uint256"
                }
              ],
              "internalType": "struct Pairing.G1Point",
              "name": "a",
              "type": "tuple"
            },
            {
              "components": [
                {
                  "internalType": "uint256[2]",
                  "name": "X",
                  "type": "uint256[2]"
                },
                {
                  "internalType": "uint256[2]",
                  "name": "Y",
                  "type": "uint256[2]"
                }
              ],
              "internalType": "struct Pairing.G2Point",
              "name": "b",
              "type": "tuple"
            },
            {
              "components": [
                {
                  "internalType": "uint256",
                  "name": "X",
                  "type": "uint256"
                },
                {
                  "internalType": "uint256",
                  "name": "Y",
                  "type": "uint256"
                }
              ],
              "internalType": "struct Pairing.G1Point",
              "name": "c",
              "type": "tuple"
            }
          ],
          "internalType": "struct MergeVerifier.Proof",
          "name": "proof",
          "type": "tuple"
        },
        {
          "internalType": "uint256[2]",
          "name": "_nullifiers",
          "type": "uint256[2]"
        },
        {
          "internalType": "uint256[3]",
          "name": "mixed_note_ids",
          "type": "uint256[3]"
        },
        {
          "internalType": "uint256[3]",
          "name": "mixed_enc_amts",
          "type": "uint256[3]"
        },
        {
          "internalType": "uint256",
          "name": "new_note_id",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "enc_amt",
          "type": "uint256"
        }
      ],
      "name": "mergeNotes",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "mv",
      "outputs": [
        {
          "internalType": "contract MergeVerifier",
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
          "name": "",
          "type": "uint256"
        }
      ],
      "name": "notes",
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
      "name": "nullifiers",
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
      "inputs": [
        {
          "components": [
            {
              "components": [
                {
                  "internalType": "uint256",
                  "name": "X",
                  "type": "uint256"
                },
                {
                  "internalType": "uint256",
                  "name": "Y",
                  "type": "uint256"
                }
              ],
              "internalType": "struct Pairing.G1Point",
              "name": "a",
              "type": "tuple"
            },
            {
              "components": [
                {
                  "internalType": "uint256[2]",
                  "name": "X",
                  "type": "uint256[2]"
                },
                {
                  "internalType": "uint256[2]",
                  "name": "Y",
                  "type": "uint256[2]"
                }
              ],
              "internalType": "struct Pairing.G2Point",
              "name": "b",
              "type": "tuple"
            },
            {
              "components": [
                {
                  "internalType": "uint256",
                  "name": "X",
                  "type": "uint256"
                },
                {
                  "internalType": "uint256",
                  "name": "Y",
                  "type": "uint256"
                }
              ],
              "internalType": "struct Pairing.G1Point",
              "name": "c",
              "type": "tuple"
            }
          ],
          "internalType": "struct SplitVerifier.Proof",
          "name": "proof",
          "type": "tuple"
        },
        {
          "internalType": "uint256",
          "name": "nullifier",
          "type": "uint256"
        },
        {
          "internalType": "uint256[3]",
          "name": "mixed_note_ids",
          "type": "uint256[3]"
        },
        {
          "internalType": "uint256[3]",
          "name": "mixed_enc_amts",
          "type": "uint256[3]"
        },
        {
          "internalType": "uint256[2]",
          "name": "new_note_ids",
          "type": "uint256[2]"
        },
        {
          "internalType": "uint256[2]",
          "name": "new_enc_amts",
          "type": "uint256[2]"
        }
      ],
      "name": "splitNotes",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "sv",
      "outputs": [
        {
          "internalType": "contract SplitVerifier",
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
          "name": "nullifier",
          "type": "uint256"
        }
      ],
      "name": "useNullifier",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    }
  ],
  "bytecode": "0x608060405234801561001057600080fd5b5060405161145238038061145283398101604081905261002f916100a4565b600080805260205260017fad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb555600280546001600160a01b039384166001600160a01b031991821617909155600380549290931691161790556100de565b6001600160a01b03811681146100a157600080fd5b50565b600080604083850312156100b757600080fd5b82516100c28161008c565b60208401519092506100d38161008c565b809150509250929050565b611365806100ed6000396000f3fe608060405234801561001057600080fd5b50600436106100b45760003560e01c80638f05cdf5116100715780638f05cdf51461012f578063b8029e161461015a578063b84e88d314610162578063ccc5d24714610175578063d21e82ab14610188578063dffc8819146101bb57600080fd5b80630e81aa22146100b95780631ccee42b146100ce57806336d44d17146100e95780635aa5bea9146100ce57806361c3a7e6146100fc5780637b77e3381461011c575b600080fd5b6100cc6100c7366004610e5b565b6101ce565b005b6100d6600281565b6040519081526020015b60405180910390f35b6100cc6100f7366004610e7d565b610259565b6100d661010a366004610e7d565b60006020819052908152604090205481565b6100cc61012a366004611064565b6102f1565b600254610142906001600160a01b031681565b6040516001600160a01b0390911681526020016100e0565b6100d6600381565b600354610142906001600160a01b031681565b6100d6610183366004610e5b565b6108e2565b6101ab610196366004610e7d565b60016020526000908152604090205460ff1681565b60405190151581526020016100e0565b6100cc6101c93660046110dc565b61090c565b6000828152602081905260409020541561021d5760405162461bcd60e51b815260206004820152600b60248201526a6e6f74652065786973747360a81b60448201526064015b60405180910390fd5b6000828152602081905260408082208390555183917f914c2fafbdebfac022bcab2301e1eabdfea3e68aa7bd8203b903dd1725e6866091a25050565b60008181526001602052604090205460ff16156102ab5760405162461bcd60e51b815260206004820152601060248201526f6e756c6c69666965722065786973747360801b6044820152606401610214565b6000818152600160208190526040808320805460ff19169092179091555182917f163699bca1c640f94b9c70d160cca7904396f4656071585813ac5aeea798a16591a250565b60008581526001602052604090205460ff16156103445760405162461bcd60e51b81526020600482015260116024820152701b9d5b1b1a599a595c881a5cc81d5cd959607a1b6044820152606401610214565b60005b60038110156103ed578481600381106103625761036261114c565b6020020151158061039b575060008060008784600381106103855761038561114c565b6020020151815260200190815260200160002054115b6103db5760405162461bcd60e51b81526020600482015260116024820152701b9bdd19481cda1bdd5b1908195e1a5cdd607a1b6044820152606401610214565b806103e581611178565b915050610347565b5060005b600281101561047c5760008084836002811061040f5761040f61114c565b602002015181526020019081526020016000205460001461046a5760405162461bcd60e51b81526020600482015260156024820152741b9bdd19481cda1bdd5b19081b9bdd08195e1a5cdd605a1b6044820152606401610214565b8061047481611178565b9150506103f1565b5060005b60038110156105175784816003811061049b5761049b61114c565b602002015115806104e957508381600381106104b9576104b961114c565b60200201516000808784600381106104d3576104d361114c565b6020020151815260200190815260200160002054145b6105055760405162461bcd60e51b815260040161021490611191565b8061050f81611178565b915050610480565b50610520610e1d565b6000805b60088110156105605761053788826108e2565b8382605881106105495761054961114c565b60200201528061055881611178565b915050610524565b5061056c6008826111d7565b905060005b60038110156105f85760005b60088110156105d8576105a688836003811061059b5761059b61114c565b6020020151826108e2565b846105b183866111d7565b605881106105c1576105c161114c565b6020020152806105d081611178565b91505061057d565b506105e46008836111d7565b9150806105f081611178565b915050610571565b5060005b60038110156106785760005b60088110156106585761062687836003811061059b5761059b61114c565b8461063183866111d7565b605881106106415761064161114c565b60200201528061065081611178565b915050610608565b506106646008836111d7565b91508061067081611178565b9150506105fc565b5060005b60028110156106f85760005b60088110156106d8576106a686836002811061059b5761059b61114c565b846106b183866111d7565b605881106106c1576106c161114c565b6020020152806106d081611178565b915050610688565b506106e46008836111d7565b9150806106f081611178565b91505061067c565b5060005b60028110156107785760005b60088110156107585761072685836002811061059b5761059b61114c565b8461073183866111d7565b605881106107415761074161114c565b60200201528061075081611178565b915050610708565b506107646008836111d7565b91508061077081611178565b9150506106fc565b50806058146107c95760405162461bcd60e51b815260206004820152601a60248201527f5468697320636f6e747261637420697320636f727275707465640000000000006044820152606401610214565b6003546040516329b92b1d60e01b81526001600160a01b03909116906329b92b1d906107fb908b908690600401611264565b602060405180830381865afa158015610818573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061083c91906112a5565b61087a5760405162461bcd60e51b815260206004820152600f60248201526e1e9ac81c1c9bdbd98819985a5b1959608a1b6044820152606401610214565b61088387610259565b60005b60028110156108d7576108c58582600281106108a4576108a461114c565b60200201518583600281106108bb576108bb61114c565b60200201516101ce565b806108cf81611178565b915050610886565b505050505050505050565b60006108ef8260206112ce565b6108fa9060e06112e5565b83901c63ffffffff1690505b92915050565b60005b600281101561099d576001600087836002811061092e5761092e61114c565b6020908102919091015182528101919091526040016000205460ff161561098b5760405162461bcd60e51b81526020600482015260116024820152701b9d5b1b1a599a595c881a5cc81d5cd959607a1b6044820152606401610214565b8061099581611178565b91505061090f565b50600082815260208190526040902054156109fa5760405162461bcd60e51b815260206004820152601960248201527f6e6577206e6f74652073686f756c64206e6f74206578697374000000000000006044820152606401610214565b60005b6003811015610a9457848160038110610a1857610a1861114c565b60200201511580610a665750838160038110610a3657610a3661114c565b6020020151600080878460038110610a5057610a5061114c565b6020020151815260200190815260200160002054145b610a825760405162461bcd60e51b815260040161021490611191565b80610a8c81611178565b9150506109fd565b50610a9d610e3c565b6000805b6002811015610b1d5760005b6008811015610afd57610acb89836002811061059b5761059b61114c565b84610ad683866111d7565b60508110610ae657610ae661114c565b602002015280610af581611178565b915050610aad565b50610b096008836111d7565b915080610b1581611178565b915050610aa1565b5060005b6003811015610b9d5760005b6008811015610b7d57610b4b88836003811061059b5761059b61114c565b84610b5683866111d7565b60508110610b6657610b6661114c565b602002015280610b7581611178565b915050610b2d565b50610b896008836111d7565b915080610b9581611178565b915050610b21565b5060005b6003811015610c1d5760005b6008811015610bfd57610bcb87836003811061059b5761059b61114c565b84610bd683866111d7565b60508110610be657610be661114c565b602002015280610bf581611178565b915050610bad565b50610c096008836111d7565b915080610c1581611178565b915050610ba1565b5060005b6008811015610c6657610c3485826108e2565b83610c3f83856111d7565b60508110610c4f57610c4f61114c565b602002015280610c5e81611178565b915050610c21565b50610c726008826111d7565b905060005b6008811015610cbc57610c8a84826108e2565b83610c9583856111d7565b60508110610ca557610ca561114c565b602002015280610cb481611178565b915050610c77565b50610cc86008826111d7565b905080605014610d1a5760405162461bcd60e51b815260206004820152601a60248201527f5468697320636f6e747261637420697320636f727275707465640000000000006044820152606401610214565b6002546040516362348eb760e11b81526001600160a01b039091169063c4691d6e90610d4c908b9086906004016112f8565b602060405180830381865afa158015610d69573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610d8d91906112a5565b610dcb5760405162461bcd60e51b815260206004820152600f60248201526e1e9ac81c1c9bdbd98819985a5b1959608a1b6044820152606401610214565b60005b6002811015610e0857610df6888260028110610dec57610dec61114c565b6020020151610259565b80610e0081611178565b915050610dce565b50610e1384846101ce565b5050505050505050565b60405180610b0001604052806058906020820280368337509192915050565b60405180610a0001604052806050906020820280368337509192915050565b60008060408385031215610e6e57600080fd5b50508035926020909101359150565b600060208284031215610e8f57600080fd5b5035919050565b634e487b7160e01b600052604160045260246000fd5b6040805190810167ffffffffffffffff81118282101715610ecf57610ecf610e96565b60405290565b600060408284031215610ee757600080fd5b610eef610eac565b9050813581526020820135602082015292915050565b600082601f830112610f1657600080fd5b6040516040810181811067ffffffffffffffff82111715610f3957610f39610e96565b8060405250806040840185811115610f5057600080fd5b845b81811015610f6a578035835260209283019201610f52565b509195945050505050565b6000818303610100811215610f8957600080fd5b6040516060810181811067ffffffffffffffff82111715610fac57610fac610e96565b604052915081610fbc8585610ed5565b81526080603f1983011215610fd057600080fd5b610fd8610eac565b9150610fe78560408601610f05565b8252610ff68560808601610f05565b602083015281602082015261100e8560c08601610ed5565b6040820152505092915050565b600082601f83011261102c57600080fd5b6040516060810181811067ffffffffffffffff8211171561104f5761104f610e96565b604052806060840185811115610f5057600080fd5b600080600080600080610260878903121561107e57600080fd5b6110888888610f75565b955061010087013594506110a088610120890161101b565b93506110b088610180890161101b565b92506110c0886101e08901610f05565b91506110d0886102208901610f05565b90509295509295509295565b60008060008060008061024087890312156110f657600080fd5b6111008888610f75565b9550611110886101008901610f05565b945061112088610140890161101b565b9350611130886101a0890161101b565b9250610200870135915061022087013590509295509295509295565b634e487b7160e01b600052603260045260246000fd5b634e487b7160e01b600052601160045260246000fd5b60006001820161118a5761118a611162565b5060010190565b60208082526026908201527f54686520616d6f756e74206f662074686973206e6f7465206973206e6f7420636040820152651bdc9c9958dd60d21b606082015260800190565b8082018082111561090657610906611162565b8060005b600281101561120d5781518452602093840193909101906001016111ee565b50505050565b61122882825180518252602090810151910152565b602081015161123b6040840182516111ea565b6020015161124c60808401826111ea565b5060400151805160c08301526020015160e090910152565b610c0081016112738285611213565b61010082018360005b605881101561129b57815183526020928301929091019060010161127c565b5050509392505050565b6000602082840312156112b757600080fd5b815180151581146112c757600080fd5b9392505050565b808202811582820484141761090657610906611162565b8181038181111561090657610906611162565b610b0081016113078285611213565b61010082018360005b605081101561129b57815183526020928301929091019060010161131056fea2646970667358221220fd23d92440748136ac3b8053238196056bc457bae2e492bc3d12cb676510daf364736f6c63430008110033",
  "deployedBytecode": "0x608060405234801561001057600080fd5b50600436106100b45760003560e01c80638f05cdf5116100715780638f05cdf51461012f578063b8029e161461015a578063b84e88d314610162578063ccc5d24714610175578063d21e82ab14610188578063dffc8819146101bb57600080fd5b80630e81aa22146100b95780631ccee42b146100ce57806336d44d17146100e95780635aa5bea9146100ce57806361c3a7e6146100fc5780637b77e3381461011c575b600080fd5b6100cc6100c7366004610e5b565b6101ce565b005b6100d6600281565b6040519081526020015b60405180910390f35b6100cc6100f7366004610e7d565b610259565b6100d661010a366004610e7d565b60006020819052908152604090205481565b6100cc61012a366004611064565b6102f1565b600254610142906001600160a01b031681565b6040516001600160a01b0390911681526020016100e0565b6100d6600381565b600354610142906001600160a01b031681565b6100d6610183366004610e5b565b6108e2565b6101ab610196366004610e7d565b60016020526000908152604090205460ff1681565b60405190151581526020016100e0565b6100cc6101c93660046110dc565b61090c565b6000828152602081905260409020541561021d5760405162461bcd60e51b815260206004820152600b60248201526a6e6f74652065786973747360a81b60448201526064015b60405180910390fd5b6000828152602081905260408082208390555183917f914c2fafbdebfac022bcab2301e1eabdfea3e68aa7bd8203b903dd1725e6866091a25050565b60008181526001602052604090205460ff16156102ab5760405162461bcd60e51b815260206004820152601060248201526f6e756c6c69666965722065786973747360801b6044820152606401610214565b6000818152600160208190526040808320805460ff19169092179091555182917f163699bca1c640f94b9c70d160cca7904396f4656071585813ac5aeea798a16591a250565b60008581526001602052604090205460ff16156103445760405162461bcd60e51b81526020600482015260116024820152701b9d5b1b1a599a595c881a5cc81d5cd959607a1b6044820152606401610214565b60005b60038110156103ed578481600381106103625761036261114c565b6020020151158061039b575060008060008784600381106103855761038561114c565b6020020151815260200190815260200160002054115b6103db5760405162461bcd60e51b81526020600482015260116024820152701b9bdd19481cda1bdd5b1908195e1a5cdd607a1b6044820152606401610214565b806103e581611178565b915050610347565b5060005b600281101561047c5760008084836002811061040f5761040f61114c565b602002015181526020019081526020016000205460001461046a5760405162461bcd60e51b81526020600482015260156024820152741b9bdd19481cda1bdd5b19081b9bdd08195e1a5cdd605a1b6044820152606401610214565b8061047481611178565b9150506103f1565b5060005b60038110156105175784816003811061049b5761049b61114c565b602002015115806104e957508381600381106104b9576104b961114c565b60200201516000808784600381106104d3576104d361114c565b6020020151815260200190815260200160002054145b6105055760405162461bcd60e51b815260040161021490611191565b8061050f81611178565b915050610480565b50610520610e1d565b6000805b60088110156105605761053788826108e2565b8382605881106105495761054961114c565b60200201528061055881611178565b915050610524565b5061056c6008826111d7565b905060005b60038110156105f85760005b60088110156105d8576105a688836003811061059b5761059b61114c565b6020020151826108e2565b846105b183866111d7565b605881106105c1576105c161114c565b6020020152806105d081611178565b91505061057d565b506105e46008836111d7565b9150806105f081611178565b915050610571565b5060005b60038110156106785760005b60088110156106585761062687836003811061059b5761059b61114c565b8461063183866111d7565b605881106106415761064161114c565b60200201528061065081611178565b915050610608565b506106646008836111d7565b91508061067081611178565b9150506105fc565b5060005b60028110156106f85760005b60088110156106d8576106a686836002811061059b5761059b61114c565b846106b183866111d7565b605881106106c1576106c161114c565b6020020152806106d081611178565b915050610688565b506106e46008836111d7565b9150806106f081611178565b91505061067c565b5060005b60028110156107785760005b60088110156107585761072685836002811061059b5761059b61114c565b8461073183866111d7565b605881106107415761074161114c565b60200201528061075081611178565b915050610708565b506107646008836111d7565b91508061077081611178565b9150506106fc565b50806058146107c95760405162461bcd60e51b815260206004820152601a60248201527f5468697320636f6e747261637420697320636f727275707465640000000000006044820152606401610214565b6003546040516329b92b1d60e01b81526001600160a01b03909116906329b92b1d906107fb908b908690600401611264565b602060405180830381865afa158015610818573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061083c91906112a5565b61087a5760405162461bcd60e51b815260206004820152600f60248201526e1e9ac81c1c9bdbd98819985a5b1959608a1b6044820152606401610214565b61088387610259565b60005b60028110156108d7576108c58582600281106108a4576108a461114c565b60200201518583600281106108bb576108bb61114c565b60200201516101ce565b806108cf81611178565b915050610886565b505050505050505050565b60006108ef8260206112ce565b6108fa9060e06112e5565b83901c63ffffffff1690505b92915050565b60005b600281101561099d576001600087836002811061092e5761092e61114c565b6020908102919091015182528101919091526040016000205460ff161561098b5760405162461bcd60e51b81526020600482015260116024820152701b9d5b1b1a599a595c881a5cc81d5cd959607a1b6044820152606401610214565b8061099581611178565b91505061090f565b50600082815260208190526040902054156109fa5760405162461bcd60e51b815260206004820152601960248201527f6e6577206e6f74652073686f756c64206e6f74206578697374000000000000006044820152606401610214565b60005b6003811015610a9457848160038110610a1857610a1861114c565b60200201511580610a665750838160038110610a3657610a3661114c565b6020020151600080878460038110610a5057610a5061114c565b6020020151815260200190815260200160002054145b610a825760405162461bcd60e51b815260040161021490611191565b80610a8c81611178565b9150506109fd565b50610a9d610e3c565b6000805b6002811015610b1d5760005b6008811015610afd57610acb89836002811061059b5761059b61114c565b84610ad683866111d7565b60508110610ae657610ae661114c565b602002015280610af581611178565b915050610aad565b50610b096008836111d7565b915080610b1581611178565b915050610aa1565b5060005b6003811015610b9d5760005b6008811015610b7d57610b4b88836003811061059b5761059b61114c565b84610b5683866111d7565b60508110610b6657610b6661114c565b602002015280610b7581611178565b915050610b2d565b50610b896008836111d7565b915080610b9581611178565b915050610b21565b5060005b6003811015610c1d5760005b6008811015610bfd57610bcb87836003811061059b5761059b61114c565b84610bd683866111d7565b60508110610be657610be661114c565b602002015280610bf581611178565b915050610bad565b50610c096008836111d7565b915080610c1581611178565b915050610ba1565b5060005b6008811015610c6657610c3485826108e2565b83610c3f83856111d7565b60508110610c4f57610c4f61114c565b602002015280610c5e81611178565b915050610c21565b50610c726008826111d7565b905060005b6008811015610cbc57610c8a84826108e2565b83610c9583856111d7565b60508110610ca557610ca561114c565b602002015280610cb481611178565b915050610c77565b50610cc86008826111d7565b905080605014610d1a5760405162461bcd60e51b815260206004820152601a60248201527f5468697320636f6e747261637420697320636f727275707465640000000000006044820152606401610214565b6002546040516362348eb760e11b81526001600160a01b039091169063c4691d6e90610d4c908b9086906004016112f8565b602060405180830381865afa158015610d69573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610d8d91906112a5565b610dcb5760405162461bcd60e51b815260206004820152600f60248201526e1e9ac81c1c9bdbd98819985a5b1959608a1b6044820152606401610214565b60005b6002811015610e0857610df6888260028110610dec57610dec61114c565b6020020151610259565b80610e0081611178565b915050610dce565b50610e1384846101ce565b5050505050505050565b60405180610b0001604052806058906020820280368337509192915050565b60405180610a0001604052806050906020820280368337509192915050565b60008060408385031215610e6e57600080fd5b50508035926020909101359150565b600060208284031215610e8f57600080fd5b5035919050565b634e487b7160e01b600052604160045260246000fd5b6040805190810167ffffffffffffffff81118282101715610ecf57610ecf610e96565b60405290565b600060408284031215610ee757600080fd5b610eef610eac565b9050813581526020820135602082015292915050565b600082601f830112610f1657600080fd5b6040516040810181811067ffffffffffffffff82111715610f3957610f39610e96565b8060405250806040840185811115610f5057600080fd5b845b81811015610f6a578035835260209283019201610f52565b509195945050505050565b6000818303610100811215610f8957600080fd5b6040516060810181811067ffffffffffffffff82111715610fac57610fac610e96565b604052915081610fbc8585610ed5565b81526080603f1983011215610fd057600080fd5b610fd8610eac565b9150610fe78560408601610f05565b8252610ff68560808601610f05565b602083015281602082015261100e8560c08601610ed5565b6040820152505092915050565b600082601f83011261102c57600080fd5b6040516060810181811067ffffffffffffffff8211171561104f5761104f610e96565b604052806060840185811115610f5057600080fd5b600080600080600080610260878903121561107e57600080fd5b6110888888610f75565b955061010087013594506110a088610120890161101b565b93506110b088610180890161101b565b92506110c0886101e08901610f05565b91506110d0886102208901610f05565b90509295509295509295565b60008060008060008061024087890312156110f657600080fd5b6111008888610f75565b9550611110886101008901610f05565b945061112088610140890161101b565b9350611130886101a0890161101b565b9250610200870135915061022087013590509295509295509295565b634e487b7160e01b600052603260045260246000fd5b634e487b7160e01b600052601160045260246000fd5b60006001820161118a5761118a611162565b5060010190565b60208082526026908201527f54686520616d6f756e74206f662074686973206e6f7465206973206e6f7420636040820152651bdc9c9958dd60d21b606082015260800190565b8082018082111561090657610906611162565b8060005b600281101561120d5781518452602093840193909101906001016111ee565b50505050565b61122882825180518252602090810151910152565b602081015161123b6040840182516111ea565b6020015161124c60808401826111ea565b5060400151805160c08301526020015160e090910152565b610c0081016112738285611213565b61010082018360005b605881101561129b57815183526020928301929091019060010161127c565b5050509392505050565b6000602082840312156112b757600080fd5b815180151581146112c757600080fd5b9392505050565b808202811582820484141761090657610906611162565b8181038181111561090657610906611162565b610b0081016113078285611213565b61010082018360005b605081101561129b57815183526020928301929091019060010161131056fea2646970667358221220fd23d92440748136ac3b8053238196056bc457bae2e492bc3d12cb676510daf364736f6c63430008110033",
  "linkReferences": {},
  "deployedLinkReferences": {}
}

export default abi;