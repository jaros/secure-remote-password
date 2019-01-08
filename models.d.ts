import SRPInteger from './lib/srp-integer'

export interface Config {
    largeSafePrime: string,
    generatorModulo: string,
    hashFunction: 'sha256' | 'sha1'
}

export interface Ephemeral {
    public: string
    secret: string
}

export interface Session {
    key: string
    proof: string
    secret: string
}

export interface Params {
    N: SRPInteger,
    g: SRPInteger,
    k: SRPInteger,
    H: (...integers: SRPInteger[]) => SRPInteger,
    PAD: (integer: SRPInteger) => SRPInteger,
    hashOutputBytes: number
}
