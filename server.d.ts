export interface Ephemeral {
  public: string
  secret: string
}

export interface Session {
  key: string
  proof: string
}

export interface Server {
    generateEphemeral: (verifier: string) => Ephemeral
    deriveSession: (serverSecretEphemeral: string, clientPublicEphemeral: string, salt: string, username: string, verifier: string, clientSessionProof: string) => Session
}

export function init(config: string): Server
