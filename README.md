## Welcome to INIChain

**INIChain** is a high-performance blockchain designed to provide privacy, scalability, and decentralization for the next generation of Web3 applications. Powered by **TfhEVM** (TFHE-based Ethereum Virtual Machine), INIChain integrates Fully Homomorphic Encryption on Torus (TFHE) with EVM compatibility, allowing encrypted data to be processed securely without decryption. This provides unparalleled privacy and security for sensitive data, making INIChain ideal for privacy-critical applications.

Learn more: https://resource.inichain.com/whitepaper.pdf

**INIChain Highlights**

INIChain offers the following key benefits and capabilities:

- **Privacy-Preserving Smart Contracts**: Leverage TFHE to enable encrypted computations, ensuring that sensitive data remains protected throughout the execution of smart contracts.

- **EVM Compatibility**: Seamlessly deploy existing Ethereum dApps without requiring code rewrites, reducing costs and time-to-market for developers.

- **Scalable and Secure**: Using **VersaHash** and **DDA (Dual Dynamic Adjustment)**, INIChain ensures secure and efficient processing of transactions while maintaining decentralization and network stability.

- **Optimized for Performance**: High throughput and low latency, designed to handle complex use cases with ease.

- **Developer-Friendly**: Supports C and C++ for intensive TFHE operations and offers low-code tools to speed up Web3 application development.

INIChain is the ideal foundation for secure, scalable, and privacy-conscious Web3 projects, offering enterprise-grade solutions for developers and businesses alike. As INIChain launches its mainnet, it will empower developers to build decentralized applications with the highest standards of privacy, security, and performance.

## INIChain Architecture

**INIChain Overview**

INIChain is a permissionless blockchain built to provide scalability, efficiency, and enhanced privacy. It is designed to support high-performance decentralized applications (dApps) by integrating the **TfhEVM** for encrypted computations and dynamic transaction management.

**High-Performance Data Processing**

INIChain's architecture supports parallel block generation to ensure that both high-privacy and standard blocks can be processed simultaneously, improving performance and reducing delays.

**Security and Efficiency with VersaHash**

VersaHash, a core component of INIChain, enhances security and efficiency through multi-stage hashing, ensuring data integrity and immutability.

**Dual Dynamic Adjustment (DDA)**

DDA allows dynamic adjustments of block difficulty and computational resources, balancing privacy and performance, optimizing resource usage, and improving scalability.

**Developer Tools**

INIChain supports **C, C++**, and **Solidity**, enabling developers to interact with the blockchain easily while maintaining the highest standards of privacy protection and data security.

## INIChain Token (INI)

INIChain’s native token, **INI**, serves as the fuel for the network, enabling transaction fees, staking, and governance. The token follows a **halving mechanism**, ensuring a gradual release of tokens to promote long-term stability and community growth.

Become a node today:https://resource.inichain.com/whitepaper.pdf


## Building the source

Many of the below are the same as or similar to go-ethereum.

For prerequisites and detailed build instructions please read the [Installation Instructions](https://geth.ethereum.org/docs/install-and-build/installing-geth).

Building `geth` requires both a Go (version 1.14 or later) and a C compiler. You can install
them using your favourite package manager. Once the dependencies are installed, run

```shell
make geth
```

or, to build the full suite of utilities:

```shell
make all
```

## Executables

The bsc project comes with several wrappers/executables found in the `cmd`
directory.

|    Command    | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| :-----------: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|  **`geth`**   | Main InitVerse Chain client binary. It is the entry point into the BSC network (main-, test- or private net), capable of running as a full node (default), archive node (retaining all historical state) or a light node (retrieving data live). It has the same and more RPC and other interface as go-ethereum and can be used by other processes as a gateway into the BSC network via JSON RPC endpoints exposed on top of HTTP, WebSocket and/or IPC transports. `geth --help` and the [CLI page](https://geth.ethereum.org/docs/interface/command-line-options) for command line options.          |
|   `clef`      | Stand-alone signing tool, which can be used as a backend signer for `geth`.  |
|   `devp2p`    | Utilities to interact with nodes on the networking layer, without running a full blockchain. |
|   `abigen`    | Source code generator to convert Ethereum contract definitions into easy to use, compile-time type-safe Go packages. It operates on plain [Ethereum contract ABIs](https://docs.soliditylang.org/en/develop/abi-spec.html) with expanded functionality if the contract bytecode is also available. However, it also accepts Solidity source files, making development much more streamlined. Please see our [Native DApps](https://geth.ethereum.org/docs/dapp/native-bindings) page for details. |
|  `bootnode`   | Stripped down version of our Ethereum client implementation that only takes part in the network node discovery protocol, but does not run any of the higher level application protocols. It can be used as a lightweight bootstrap node to aid in finding peers in private networks.                                                                                                                                                                                                                                                                 |
|     `evm`     | Developer utility version of the EVM (Ethereum Virtual Machine) that is capable of running bytecode snippets within a configurable environment and execution mode. Its purpose is to allow isolated, fine-grained debugging of EVM opcodes (e.g. `evm --code 60ff60ff --debug run`).                                                                                                                                                                                                                                                                     |
|   `rlpdump`   | Developer utility tool to convert binary RLP ([Recursive Length Prefix](https://eth.wiki/en/fundamentals/rlp)) dumps (data encoding used by the Ethereum protocol both network as well as consensus wise) to user-friendlier hierarchical representation (e.g. `rlpdump --hex CE0183FFFFFFC4C304050583616263`).                                                                                                                                                                                                                                 |

## Running `geth`

Going through all the possible command line flags is out of scope here (please consult our
[CLI Wiki page](https://geth.ethereum.org/docs/interface/command-line-options)),
but we've enumerated a few common parameter combos to get you up to speed quickly
on how you can run your own `geth` instance.

### Hardware Requirements

The hardware must meet certain requirements to run a full node.
- VPS running recent versions of Mac OS X or Linux.
- 1T of SSD storage for mainnet, 500G of SSD storage for testnet.
- 8 cores of CPU and 32 gigabytes of memory (RAM) for mainnet.
- 4 cores of CPU and 8 gigabytes of memory (RAM) for testnet.
- A broadband Internet connection with upload/download speeds of at least 10 megabyte per second

```shell
$ geth console
```

This command will:
 * Start `geth` in fast sync mode (default, can be changed with the `--syncmode` flag),
   causing it to download more data in exchange for avoiding processing the entire history
   of the InitVerse Chain network, which is very CPU intensive.
 * Start up `geth`'s built-in interactive [JavaScript console](https://geth.ethereum.org/docs/interface/javascript-console),
   (via the trailing `console` subcommand) through which you can interact using [`web3` methods](https://web3js.readthedocs.io/en/) 
   (note: the `web3` version bundled within `geth` is very old, and not up to date with official docs),
   as well as `geth`'s own [management APIs](https://geth.ethereum.org/docs/rpc/server).
   This tool is optional and if you leave it out you can always attach to an already running
   `geth` instance with `geth attach`.

### Configuration

As an alternative to passing the numerous flags to the `geth` binary, you can also pass a
configuration file via:

```shell
$ geth --config /path/to/your_config.toml
```

To get an idea how the file should look like you can use the `dumpconfig` subcommand to
export your existing configuration:

```shell
$ geth --your-favourite-flags dumpconfig
```

### Programmatically interfacing `geth` nodes

As a developer, sooner rather than later you'll want to start interacting with `geth` and the
InitVerse Chain network via your own programs and not manually through the console. To aid
this, `geth` has built-in support for a JSON-RPC based APIs ([standard APIs](https://eth.wiki/json-rpc/API)
and [`geth` specific APIs](https://geth.ethereum.org/docs/rpc/server)).
These can be exposed via HTTP, WebSockets and IPC (UNIX sockets on UNIX based
platforms, and named pipes on Windows).

The IPC interface is enabled by default and exposes all the APIs supported by `geth`,
whereas the HTTP and WS interfaces need to manually be enabled and only expose a
subset of APIs due to security reasons. These can be turned on/off and configured as
you'd expect.

HTTP based JSON-RPC API options:

  * `--http` Enable the HTTP-RPC server
  * `--http.addr` HTTP-RPC server listening interface (default: `localhost`)
  * `--http.port` HTTP-RPC server listening port (default: `8545`)
  * `--http.api` API's offered over the HTTP-RPC interface (default: `eth,net,web3`)
  * `--http.corsdomain` Comma separated list of domains from which to accept cross origin requests (browser enforced)
  * `--ws` Enable the WS-RPC server
  * `--ws.addr` WS-RPC server listening interface (default: `localhost`)
  * `--ws.port` WS-RPC server listening port (default: `8546`)
  * `--ws.api` API's offered over the WS-RPC interface (default: `eth,net,web3`)
  * `--ws.origins` Origins from which to accept websockets requests
  * `--ipcdisable` Disable the IPC-RPC server
  * `--ipcapi` API's offered over the IPC-RPC interface (default: `admin,debug,eth,miner,net,personal,shh,txpool,web3`)
  * `--ipcpath` Filename for IPC socket/pipe within the datadir (explicit paths escape it)

You'll need to use your own programming environments' capabilities (libraries, tools, etc) to
connect via HTTP, WS or IPC to a `geth` node configured with the above flags and you'll
need to speak [JSON-RPC](https://www.jsonrpc.org/specification) on all transports. You
can reuse the same connection for multiple requests!

**Note: Please understand the security implications of opening up an HTTP/WS based
transport before doing so! Hackers on the internet are actively trying to subvert
BSC nodes with exposed APIs! Further, all browser tabs can access locally
running web servers, so malicious web pages could try to subvert locally available
APIs!**

## Contribution

Thank you for considering to help out with the source code! We welcome contributions
from anyone on the internet, and are grateful for even the smallest of fixes!

If you'd like to contribute to InitVerse, please fork, fix, commit and send a pull request
for the maintainers to review and merge into the main code base. If you wish to submit
more complex changes though, please check up with the core devs first on [our discord channel](https://discord.com/invite/InitVerse)
to ensure those changes are in line with the general philosophy of the project and/or get
some early feedback which can make both your efforts much lighter as well as our review
and merge procedures quick and simple.

Please make sure your contributions adhere to our coding guidelines:

 * Code must adhere to the official Go [formatting](https://golang.org/doc/effective_go.html#formatting)
   guidelines (i.e. uses [gofmt](https://golang.org/cmd/gofmt/)).
 * Code must be documented adhering to the official Go [commentary](https://golang.org/doc/effective_go.html#commentary)
   guidelines.
 * Pull requests need to be based on and opened against the `master` branch.
 * Commit messages should be prefixed with the package(s) they modify.
   * E.g. "eth, rpc: make trace configs optional"

Please see the [Developers' Guide](https://geth.ethereum.org/docs/developers/geth-developer/dev-guide)
for more details on configuring your environment, managing project dependencies, and
testing procedures.

## License

The InitVerse library (i.e. all code outside of the `cmd` directory) is licensed under the
[GNU Lesser General Public License v3.0](https://www.gnu.org/licenses/lgpl-3.0.en.html),
also included in our repository in the `COPYING.LESSER` file.

The InitVerse binaries (i.e. all code inside of the `cmd` directory) is licensed under the
[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html), also
included in our repository in the `COPYING` file.
