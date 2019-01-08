import {Config, Ephemeral, Params, Session} from "./models";

export interface Client {
    generateSalt: () => string,
    derivePrivateKey: (salt: string, username: string, password: string) => string
    deriveVerifier: (privateKey: string) => string
    generateEphemeral: () => Ephemeral
    deriveSession: (clientSecretEphemeral: string, serverPublicEphemeral: string, salt: string, username: string, privateKey: string) => Session
    verifySession: (clientPublicEphemeral: string, clientSession: Session, serverSessionProof: string) => void,
    params: () => Params
}

export function init(config: Config | string): Client
