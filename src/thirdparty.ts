import * as crypto from 'crypto'
import * as ethUtil from 'ethereumjs-util'

import Wallet from './index'

const scryptsy = require('scrypt.js')
const utf8 = require('utf8')
const aesjs = require('aes-js')

function runCipherBuffer(cipher: crypto.Cipher | crypto.Decipher, data: Buffer): Buffer {
  return Buffer.concat([cipher.update(data), cipher.final()])
}

// evp_kdf

export interface EvpKdfOpts {
  count: number
  keysize: number
  ivsize: number
  digest: string
}

const evpKdfDefaults: EvpKdfOpts = {
  count: 1,
  keysize: 16,
  ivsize: 16,
  digest: 'md5',
}

function mergeEvpKdfOptsWithDefaults(opts?: Partial<EvpKdfOpts>): EvpKdfOpts {
  if (!opts) {
    return evpKdfDefaults
  }
  return {
    count: opts.count || evpKdfDefaults.count,
    keysize: opts.keysize || evpKdfDefaults.keysize,
    ivsize: opts.ivsize || evpKdfDefaults.ivsize,
    digest: opts.digest || evpKdfDefaults.digest,
  }
}

/*
 * opts:
 * - digest - digest algorithm, defaults to md5
 * - count - hash iterations
 * - keysize - desired key size
 * - ivsize - desired IV size
 *
 * Algorithm form https://www.openssl.org/docs/manmaster/crypto/EVP_BytesToKey.html
 *
 * FIXME: not optimised at all
 */
function evp_kdf(data: Buffer, salt: Buffer, opts?: Partial<EvpKdfOpts>) {
  const params = mergeEvpKdfOptsWithDefaults(opts)

  // A single EVP iteration, returns `D_i`, where block equlas to `D_(i-1)`
  function iter(block: Buffer) {
    let hash = crypto.createHash(params.digest)
    hash.update(block)
    hash.update(data)
    hash.update(salt)
    block = hash.digest()

    for (let i = 1, len = params.count; i < len; i++) {
      hash = crypto.createHash(params.digest)
      hash.update(block)
      block = hash.digest()
    }
    return block
  }

  const ret: Buffer[] = []
  let i = 0
  while (Buffer.concat(ret).length < params.keysize + params.ivsize) {
    ret[i] = iter(i === 0 ? Buffer.alloc(0) : ret[i - 1])
    i++
  }
  const tmp = Buffer.concat(ret)

  return {
    key: tmp.slice(0, params.keysize),
    iv: tmp.slice(params.keysize, params.keysize + params.ivsize),
  }
}

// http://stackoverflow.com/questions/25288311/cryptojs-aes-pattern-always-ends-with
function decodeCryptojsSalt(input: string): { ciphertext: Buffer; salt?: Buffer } {
  const ciphertext = Buffer.from(input, 'base64')
  if (ciphertext.slice(0, 8).toString() === 'Salted__') {
    return {
      salt: ciphertext.slice(8, 16),
      ciphertext: ciphertext.slice(16),
    }
  }
  return { ciphertext }
}

// {
//   "address": "0x169aab499b549eac087035e640d3f7d882ef5e2d",
//   "encrypted": true,
//   "locked": true,
//   "hash": "342f636d174cc1caa49ce16e5b257877191b663e0af0271d2ea03ac7e139317d",
//   "private": "U2FsdGVkX19ZrornRBIfl1IDdcj6S9YywY8EgOeOtLj2DHybM/CHL4Jl0jcwjT+36kDnjj+qEfUBu6J1mGQF/fNcD/TsAUgGUTEUEOsP1CKDvNHfLmWLIfxqnYHhHsG5",
//   "public": "U2FsdGVkX19EaDNK52q7LEz3hL/VR3dYW5VcoP04tcVKNS0Q3JINpM4XzttRJCBtq4g22hNDrOR8RWyHuh3nPo0pRSe9r5AUfEiCLaMBAhI16kf2KqCA8ah4brkya9ZLECdIl0HDTMYfDASBnyNXd87qodt46U0vdRT3PppK+9hsyqP8yqm9kFcWqMHktqubBE937LIU0W22Rfw6cJRwIw=="
// }

export interface EtherWalletOptions {
  address: string
  encrypted: boolean
  locked: boolean
  hash: string
  private: string
  public: string
}

/*
 * This wallet format is created by https://github.com/SilentCicero/ethereumjs-accounts
 * and used on https://www.myetherwallet.com/
 */
export function fromEtherWallet(input: string | EtherWalletOptions, password: string): Wallet {
  const json: EtherWalletOptions = typeof input === 'object' ? input : JSON.parse(input)

  let privateKey: Buffer
  if (!json.locked) {
    if (json.private.length !== 64) {
      throw new Error('Invalid private key length')
    }
    privateKey = Buffer.from(json.private, 'hex')
  } else {
    if (typeof password !== 'string') {
      throw new Error('Password required')
    }

    if (password.length < 7) {
      throw new Error('Password must be at least 7 characters')
    }

    // the "encrypted" version has the low 4 bytes
    // of the hash of the address appended
    const hash = json.encrypted ? json.private.slice(0, 128) : json.private

    // decode openssl ciphertext + salt encoding
    const cipher = decodeCryptojsSalt(hash)
    if (!cipher.salt) {
      throw new Error('Unsupported EtherWallet key format')
    }

    // derive key/iv using OpenSSL EVP as implemented in CryptoJS
    const evp = evp_kdf(Buffer.from(password), cipher.salt, { keysize: 32, ivsize: 16 })

    const decipher = crypto.createDecipheriv('aes-256-cbc', evp.key, evp.iv)
    privateKey = runCipherBuffer(decipher, Buffer.from(cipher.ciphertext))

    // NOTE: yes, they've run it through UTF8
    privateKey = Buffer.from(utf8.decode(privateKey.toString()), 'hex')
  }

  const wallet = new Wallet(privateKey)
  if (wallet.getAddressString() !== json.address) {
    throw new Error('Invalid private key or address')
  }
  return wallet
}

export function fromEtherCamp(passphrase: string): Wallet {
  return new Wallet(ethUtil.keccak256(Buffer.from(passphrase)))
}

export function fromKryptoKit(entropy: string, password: string): Wallet {
  function kryptoKitBrokenScryptSeed(buf: Buffer) {
    // js-scrypt calls `Buffer.from(String(salt), 'utf8')` on the seed even though it is a buffer
    //
    // The `buffer`` implementation used does the below transformation (doesn't matches the current version):
    // https://github.com/feross/buffer/blob/67c61181b938b17d10dbfc0a545f713b8bd59de8/index.js

    function decodeUtf8Char(str: string) {
      try {
        return decodeURIComponent(str)
      } catch (err) {
        return String.fromCharCode(0xfffd) // UTF 8 invalid char
      }
    }

    let res = '',
      tmp = ''
    for (let i = 0; i < buf.length; i++) {
      if (buf[i] <= 0x7f) {
        res += decodeUtf8Char(tmp) + String.fromCharCode(buf[i])
        tmp = ''
      } else {
        tmp += '%' + buf[i].toString(16)
      }
    }
    return Buffer.from(res + decodeUtf8Char(tmp))
  }

  if (entropy[0] === '#') {
    entropy = entropy.slice(1)
  }

  const type = entropy[0]
  entropy = entropy.slice(1)

  let privateKey: Buffer
  if (type === 'd') {
    privateKey = ethUtil.sha256(entropy)
  } else if (type === 'q') {
    if (typeof password !== 'string') {
      throw new Error('Password required')
    }

    const encryptedSeed = ethUtil.sha256(Buffer.from(entropy.slice(0, 30)))
    const checksum = entropy.slice(30, 46)

    const salt = kryptoKitBrokenScryptSeed(encryptedSeed)
    const aesKey = scryptsy(Buffer.from(password, 'utf8'), salt, 16384, 8, 1, 32)

    /* FIXME: try to use `crypto` instead of `aesjs`

    // NOTE: ECB doesn't use the IV, so it can be anything
    var decipher = crypto.createDecipheriv("aes-256-ecb", aesKey, Buffer.from(0))

    // FIXME: this is a clear abuse, but seems to match how ECB in aesjs works
    privKey = Buffer.concat([
      decipher.update(encryptedSeed).slice(0, 16),
      decipher.update(encryptedSeed).slice(0, 16),
    ])
    */

    const decipher = new aesjs.ModeOfOperation.ecb(aesKey)
    /* decrypt returns an Uint8Array, perhaps there is a better way to concatenate */
    privateKey = Buffer.concat([
      Buffer.from(decipher.decrypt(encryptedSeed.slice(0, 16))),
      Buffer.from(decipher.decrypt(encryptedSeed.slice(16, 32))),
    ])

    if (checksum.length > 0) {
      if (
        checksum !==
        ethUtil
          .sha256(ethUtil.sha256(privateKey))
          .slice(0, 8)
          .toString('hex')
      ) {
        throw new Error('Failed to decrypt input - possibly invalid passphrase')
      }
    }
  } else {
    throw new Error('Unsupported or invalid entropy type')
  }

  return new Wallet(privateKey)
}

export function fromQuorumWallet(passphrase: string, userid: string): Wallet {
  if (passphrase.length < 10) {
    throw new Error('Passphrase must be at least 10 characters')
  }
  if (userid.length < 10) {
    throw new Error('User id must be at least 10 characters')
  }

  const merged = passphrase + userid
  const seed = crypto.pbkdf2Sync(merged, merged, 2000, 32, 'sha256')
  return new Wallet(seed)
}

const Thirdparty = {
  fromEtherWallet,
  fromEtherCamp,
  fromKryptoKit,
  fromQuorumWallet,
}

export default Thirdparty
