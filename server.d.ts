import {Config, Ephemeral, Session} from "./models";

export interface Server {
    generateEphemeral: (verifier: string) => Ephemeral
    deriveSession: (serverSecretEphemeral: string, clientPublicEphemeral: string, salt: string, username: string, verifier: string, clientSessionProof: string) => Session
}

export function init(config: Config | string): Server
