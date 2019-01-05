import SRPInteger from './lib/srp-integer'

export interface Ephemeral {
  public: string
  secret: string
}

export interface Session {
  key: string
  proof: string
}

export interface Params {
    N: SRPInteger,
    g: SRPInteger,
    k: SRPInteger,
    H: (...integers: SRPInteger[]) => SRPInteger,
    PAD: (integer: SRPInteger) => SRPInteger,
    hashOutputBytes: number
}

export interface Client {
    generateSalt: () => string,
    derivePrivateKey: (salt: string, username: string, password: string) => string
    deriveVerifier: (privateKey: string) => string
    generateEphemeral: () => Ephemeral
    deriveSession: (clientSecretEphemeral: string, serverPublicEphemeral: string, salt: string, username: string, privateKey: string) => Session
    verifySession: (clientPublicEphemeral: string, clientSession: Session, serverSessionProof: string) => void,
    params: () => Params
}

export function init(bitGroup: string): Client
