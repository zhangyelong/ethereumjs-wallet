[ethereumjs-wallet](../README.md) > [EthereumHDKey](../classes/ethereumhdkey.md)

# Class: EthereumHDKey

## Hierarchy

**EthereumHDKey**

## Index

### Constructors

- [constructor](ethereumhdkey.md#constructor)

### Properties

- [\_hdkey](ethereumhdkey.md#_hdkey)

### Methods

- [deriveChild](ethereumhdkey.md#derivechild)
- [derivePath](ethereumhdkey.md#derivepath)
- [getWallet](ethereumhdkey.md#getwallet)
- [privateExtendedKey](ethereumhdkey.md#privateextendedkey)
- [publicExtendedKey](ethereumhdkey.md#publicextendedkey)
- [fromExtendedKey](ethereumhdkey.md#fromextendedkey)
- [fromMasterSeed](ethereumhdkey.md#frommasterseed)

---

## Constructors

<a id="constructor"></a>

### constructor

⊕ **new EthereumHDKey**(\_hdkey?: _`any`_): [EthereumHDKey](ethereumhdkey.md)

_Defined in [hdkey.ts:12](https://github.com/alcuadrado/ethereumjs-wallet/blob/8b5f5a9/src/hdkey.ts#L12)_

**Parameters:**

| Name               | Type  |
| ------------------ | ----- |
| `Optional` \_hdkey | `any` |

**Returns:** [EthereumHDKey](ethereumhdkey.md)

---

## Properties

<a id="_hdkey"></a>

### ` <Private>``<Optional> ` \_hdkey

**● \_hdkey**: _`any`_

_Defined in [hdkey.ts:14](https://github.com/alcuadrado/ethereumjs-wallet/blob/8b5f5a9/src/hdkey.ts#L14)_

---

## Methods

<a id="derivechild"></a>

### deriveChild

▸ **deriveChild**(index: _`number`_): [EthereumHDKey](ethereumhdkey.md)

_Defined in [hdkey.ts:31](https://github.com/alcuadrado/ethereumjs-wallet/blob/8b5f5a9/src/hdkey.ts#L31)_

**Parameters:**

| Name  | Type     |
| ----- | -------- |
| index | `number` |

**Returns:** [EthereumHDKey](ethereumhdkey.md)

---

<a id="derivepath"></a>

### derivePath

▸ **derivePath**(path: _`string`_): [EthereumHDKey](ethereumhdkey.md)

_Defined in [hdkey.ts:27](https://github.com/alcuadrado/ethereumjs-wallet/blob/8b5f5a9/src/hdkey.ts#L27)_

**Parameters:**

| Name | Type     |
| ---- | -------- |
| path | `string` |

**Returns:** [EthereumHDKey](ethereumhdkey.md)

---

<a id="getwallet"></a>

### getWallet

▸ **getWallet**(): [Wallet](wallet.md)

_Defined in [hdkey.ts:35](https://github.com/alcuadrado/ethereumjs-wallet/blob/8b5f5a9/src/hdkey.ts#L35)_

**Returns:** [Wallet](wallet.md)

---

<a id="privateextendedkey"></a>

### privateExtendedKey

▸ **privateExtendedKey**(): `Buffer`

_Defined in [hdkey.ts:16](https://github.com/alcuadrado/ethereumjs-wallet/blob/8b5f5a9/src/hdkey.ts#L16)_

**Returns:** `Buffer`

---

<a id="publicextendedkey"></a>

### publicExtendedKey

▸ **publicExtendedKey**(): `Buffer`

_Defined in [hdkey.ts:23](https://github.com/alcuadrado/ethereumjs-wallet/blob/8b5f5a9/src/hdkey.ts#L23)_

**Returns:** `Buffer`

---

<a id="fromextendedkey"></a>

### `<Static>` fromExtendedKey

▸ **fromExtendedKey**(base58Key: _`string`_): [EthereumHDKey](ethereumhdkey.md)

_Defined in [hdkey.ts:10](https://github.com/alcuadrado/ethereumjs-wallet/blob/8b5f5a9/src/hdkey.ts#L10)_

**Parameters:**

| Name      | Type     |
| --------- | -------- |
| base58Key | `string` |

**Returns:** [EthereumHDKey](ethereumhdkey.md)

---

<a id="frommasterseed"></a>

### `<Static>` fromMasterSeed

▸ **fromMasterSeed**(seedBuffer: _`Buffer`_): [EthereumHDKey](ethereumhdkey.md)

_Defined in [hdkey.ts:6](https://github.com/alcuadrado/ethereumjs-wallet/blob/8b5f5a9/src/hdkey.ts#L6)_

**Parameters:**

| Name       | Type     |
| ---------- | -------- |
| seedBuffer | `Buffer` |

**Returns:** [EthereumHDKey](ethereumhdkey.md)

---
