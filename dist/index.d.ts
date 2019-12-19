/// <reference types="node" />
interface V3Params {
    kdf: string;
    cipher: string;
    salt: string | Buffer;
    iv: string | Buffer;
    uuid: string | Buffer;
    dklen: number;
    c: number;
    n: number;
    r: number;
    p: number;
}
interface ScryptKDFParamsOut {
    dklen: number;
    n: number;
    p: number;
    r: number;
    salt: string;
}
interface PBKDFParamsOut {
    c: number;
    dklen: number;
    prf: string;
    salt: string;
}
declare type KDFParamsOut = ScryptKDFParamsOut | PBKDFParamsOut;
interface V1Keystore {
    Address: string;
    Crypto: {
        CipherText: string;
        IV: string;
        KeyHeader: {
            Kdf: string;
            KdfParams: {
                DkLen: number;
                N: number;
                P: number;
                R: number;
                SaltLen: number;
            };
            Version: string;
        };
        MAC: string;
        Salt: string;
    };
    Id: string;
    Version: string;
}
interface V3Keystore {
    crypto: {
        cipher: string;
        cipherparams: {
            iv: string;
        };
        ciphertext: string;
        kdf: string;
        kdfparams: KDFParamsOut;
        mac: string;
    };
    id: string;
    version: number;
}
interface EthSaleKeystore {
    encseed: string;
    ethaddr: string;
    btcaddr: string;
    email: string;
}
export default class Wallet {
    private readonly privateKey?;
    private publicKey;
    constructor(privateKey?: Buffer | undefined, publicKey?: Buffer | undefined);
    /**
     * Create an instance based on a new random key.
     *
     * @param icapDirect setting this to `true` will generate an address suitable for the `ICAP Direct mode`
     */
    static generate(icapDirect?: boolean): Wallet;
    /**
     * Create an instance where the address is valid against the supplied pattern (**this will be very slow**)
     */
    static generateVanityAddress(pattern: RegExp | string): Wallet;
    /**
     * Create an instance based on a public key (certain methods will not be available)
     *
     * This method only accepts uncompressed Ethereum-style public keys, unless
     * the `nonStrict` flag is set to true.
     */
    static fromPublicKey(publicKey: Buffer, nonStrict?: boolean): Wallet;
    /**
     * Create an instance based on a BIP32 extended public key (xpub)
     */
    static fromExtendedPublicKey(extendedPublicKey: string): Wallet;
    /**
     * Create an instance based on a raw private key
     */
    static fromPrivateKey(privateKey: Buffer): Wallet;
    /**
     * Create an instance based on a BIP32 extended private key (xprv)
     */
    static fromExtendedPrivateKey(extendedPrivateKey: string): Wallet;
    /**
     * Import a wallet (Version 1 of the Ethereum wallet format)
     */
    static fromV1(input: string | V1Keystore, password: string): Wallet;
    /**
     * Import a wallet (Version 3 of the Ethereum wallet format). Set `nonStrict` true to accept files with mixed-caps.
     */
    static fromV3(input: string | V3Keystore, password: string, nonStrict?: boolean): Wallet;
    static fromEthSale(input: string | EthSaleKeystore, password: string): Wallet;
    private get pubKey();
    private get privKey();
    getPrivateKey(): Buffer;
    getPrivateKeyString(): string;
    getPublicKey(): Buffer;
    getPublicKeyString(): string;
    getAddress(): Buffer;
    getAddressString(): string;
    getChecksumAddressString(): string;
    toV3(password: string, opts?: Partial<V3Params>): V3Keystore;
    getV3Filename(timestamp?: number): string;
    toV3String(password: string, opts?: Partial<V3Params>): string;
}
export {};
