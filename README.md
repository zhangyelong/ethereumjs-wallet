# ethereumjs-wallet

[![NPM Package](https://img.shields.io/npm/v/ethereumjs-wallet.svg?style=flat-square)](https://www.npmjs.org/package/ethereumjs-wallet)
[![Build Status](https://travis-ci.org/ethereumjs/ethereumjs-wallet.svg?branch=master)](https://travis-ci.org/ethereumjs/ethereumjs-wallet)
[![Coverage Status](https://img.shields.io/coveralls/ethereumjs/ethereumjs-wallet.svg?style=flat-square)](https://coveralls.io/r/ethereumjs/ethereumjs-wallet)
[![Gitter](https://img.shields.io/gitter/room/ethereum/ethereumjs-lib.svg?style=flat-square)](https://gitter.im/ethereum/ethereumjs-lib) or #ethereumjs on freenode

A lightweight wallet implementation. At the moment it supports key creation and conversion between various formats.

It is complemented by the following packages:

- [ethereumjs-tx](https://github.com/ethereumjs/ethereumjs-tx) to sign transactions
- [ethereumjs-icap](https://github.com/ethereumjs/ethereumjs-icap) to manipulate ICAP addresses
- [store.js](https://github.com/marcuswestin/store.js) to use browser storage

Motivations are:

- be lightweight
- work in a browser
- use a single, maintained version of crypto library (and that should be in line with `ethereumjs-util` and `ethereumjs-tx`)
- support import/export between various wallet formats
- support BIP32 HD keys

Features not supported:

- signing transactions
- managing storage (neither in node.js or the browser)

## Wallet API

For information about the Wallet's API, please go to [./docs/classes/wallet.md](./docs/classes/wallet.md).

## Thirdparty API

Importing various third party wallets is possible through the `thirdparty` submodule:

`const thirdparty = require('ethereumjs-wallet/thirdparty')`

Please go to [./docs/README.md](./docs/README.md) for more info.

## HD Wallet API

To use BIP32 HD wallets, first include the `hdkey` submodule:

`const hdkey = require('ethereumjs-wallet/hdkey')`

Please go to [./docs/classes/ethereumhdkey.md](./docs/classes/ethereumhdkey.md) for more info.

## Provider Engine

The Wallet can be easily plugged into [provider-engine](https://github.com/metamask/provider-engine) to provide signing:

```js
const WalletSubprovider = require('ethereumjs-wallet/provider-engine')

<engine>.addProvider(new WalletSubprovider(<wallet instance>))
```

Note it only supports the basic wallet. With a HD Wallet, call `getWallet()` first.

### Remarks about `toV3`

The `options` is an optional object hash, where all the serialization parameters can be fine tuned:

- uuid - UUID. One is randomly generated.
- salt - Random salt for the `kdf`. Size must match the requirements of the KDF (key derivation function). Random number generated via `crypto.getRandomBytes` if nothing is supplied.
- iv - Initialization vector for the `cipher`. Size must match the requirements of the cipher. Random number generated via `crypto.getRandomBytes` if nothing is supplied.
- kdf - The key derivation function, see below.
- dklen - Derived key length. For certain `cipher` settings, this must match the block sizes of those.
- cipher - The cipher to use. Names must match those of supported by `OpenSSL`, e.g. `aes-128-ctr` or `aes-128-cbc`.

Depending on the `kdf` selected, the following options are available too.

For `pbkdf2`:

- `c` - Number of iterations. Defaults to 262144.
- `prf` - The only supported (and default) value is `hmac-sha256`. So no point changing it.

For `scrypt`:

- `n` - Iteration count. Defaults to 262144.
- `r` - Block size for the underlying hash. Defaults to 8.
- `p` - Parallelization factor. Defaults to 1.

The following settings are favoured by the Go Ethereum implementation and we default to the same:

- `kdf`: `scrypt`
- `dklen`: `32`
- `n`: `262144`
- `r`: `8`
- `p`: `1`
- `cipher`: `aes-128-ctr`

# EthereumJS

See our organizational [documentation](https://ethereumjs.readthedocs.io) for an introduction to `EthereumJS` as well as information on current standards and best practices.

If you want to join for work or do improvements on the libraries have a look at our [contribution guidelines](https://ethereumjs.readthedocs.io/en/latest/contributing.html).

## License

MIT License

Copyright (C) 2016 Alex Beregszaszi
