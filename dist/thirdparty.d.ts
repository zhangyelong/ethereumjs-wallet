import Wallet from './index';
export interface EvpKdfOpts {
    count: number;
    keysize: number;
    ivsize: number;
    digest: string;
}
export interface EtherWalletOptions {
    address: string;
    encrypted: boolean;
    locked: boolean;
    hash: string;
    private: string;
    public: string;
}
export declare function fromEtherWallet(input: string | EtherWalletOptions, password: string): Wallet;
export declare function fromEtherCamp(passphrase: string): Wallet;
export declare function fromKryptoKit(entropy: string, password: string): Wallet;
export declare function fromQuorumWallet(passphrase: string, userid: string): Wallet;
declare const Thirdparty: {
    fromEtherWallet: typeof fromEtherWallet;
    fromEtherCamp: typeof fromEtherCamp;
    fromKryptoKit: typeof fromKryptoKit;
    fromQuorumWallet: typeof fromQuorumWallet;
};
export default Thirdparty;
