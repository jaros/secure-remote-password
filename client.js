'use strict'

const paramsFun = require('./lib/params')
const SRPInteger = require('./lib/srp-integer')

/**
 *
 * @param config is either config object that defines input params (N,g,...) or the name of bit group that will provide preconfigured params
 * <p>
 * bit group name can be '1024-bit', '2048-bit' and 'default' that falls back to '2048-bit'
 * @returns {{params: (function(): {N, g, k, H, PAD, hashOutputBytes}), generateSalt: (function()), derivePrivateKey: (function(*=, *=, *=): *), deriveVerifier: (function(*=)), generateEphemeral: (function(): {secret, public}), deriveEphemeralPublicKey: (function(*=): SRPInteger), deriveSession: (function(*=, *=, *=, *=, *=): {key: *, proof: *, secret}), calculateSecretEvidence: (function(*=, *=, *=, *, *): *), calculateS: (function(*, *, *, *=): SRPInteger), calculateU: (function(*=, *=): *), verifySession: verifySession}}
 */
exports.init = (config) => {
  const params = paramsFun(config)

  const deriveEphemeralPublicKey = (a) => {
    // N      A large safe prime (N = 2q+1, where q is prime)
    // g      A generator modulo N
    const { N, g } = params

    // A = g^a                  (a = random number)
    return g.modPow(a, N)
  }

  const calculateS = (B, a, u, x) => {
    const { N, g, k } = params
    // S = (B - kg^x) ^ (a + ux)
    return B.subtract(k.multiply(g.modPow(x, N))).modPow(a.add(u.multiply(x)), N)
  }

  const calculateU = (A, B) => {
    const { H, PAD } = params
    // u = H(PAD(A), PAD(B))
    return H(PAD(A), PAD(B))
  }

  const calculateSecretEvidence = (A, B, S, s, I) => {
    const { H, PAD } = params

    // M = H(H(N) xor H(g), H(I), s, A, B, K)
    // return H(H(N).xor(H(g)), H(I), s, A, B, K)

    // TODO for compatibility with server implementation use following formula for M1 calculation
    // M = H(A,B,S)
    return H(PAD(A), PAD(B), PAD(S))
  }

  return {
    params: () => params,

    generateSalt: () => {
      // s      User's salt
      const s = SRPInteger.randomInteger(params.hashOutputBytes)

      return s.toHex()
    },

    derivePrivateKey: (salt, username, password) => {
      // H()    One-way hash function
      const { H } = params

      // s      User's salt
      // I      Username
      // p      Cleartext Password
      const s = SRPInteger.fromHex(salt)
      const I = String(username)
      const p = String(password)

      // x = H(s, H(I | ':' | p))  (s is chosen randomly)
      const x = H(s, H(`${I}:${p}`))

      return x.toHex()
    },

    deriveVerifier: (privateKey) => {
      // N      A large safe prime (N = 2q+1, where q is prime)
      // g      A generator modulo N
      const { N, g } = params

      // x      Private key (derived from p and s)
      const x = SRPInteger.fromHex(privateKey)

      // v = g^x                   (computes password verifier)
      const v = g.modPow(x, N)

      return v.toHex()
    },

    generateEphemeral: () => {
      // A = g^a                  (a = random number)
      const a = SRPInteger.randomInteger(params.hashOutputBytes)
      const A = deriveEphemeralPublicKey(a)

      return {
        secret: a.toHex(),
        public: A.toHex()
      }
    },

    deriveEphemeralPublicKey: deriveEphemeralPublicKey,

    deriveSession: (clientSecretEphemeral, serverPublicEphemeral, salt, username, privateKey) => {
      // N      A large safe prime (N = 2q+1, where q is prime)
      // g      A generator modulo N
      // k      Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
      // H()    One-way hash function
      // PAD()  Pad the number to have the same number of bytes as N
      const { N, g, k, H, PAD } = params

      // a      Secret ephemeral values
      // B      Public ephemeral values
      // s      User's salt
      // I      Username
      // x      Private key (derived from p and s)
      const a = SRPInteger.fromHex(clientSecretEphemeral)
      const B = SRPInteger.fromHex(serverPublicEphemeral)
      const s = SRPInteger.fromHex(salt)
      const I = String(username)
      const x = SRPInteger.fromHex(privateKey)

      // A = g^a                  (a = random number)
      const A = deriveEphemeralPublicKey(a)

      // B % N > 0
      if (B.mod(N).equals(SRPInteger.ZERO)) {
        // fixme: .code, .statusCode, etc.
        throw new Error('The server sent an invalid public ephemeral')
      }

      // u = H(PAD(A), PAD(B))
      const u = calculateU(A, B)

      // S = (B - kg^x) ^ (a + ux)
      const S = calculateS(B, a, u, x)

      // K = H(S)
      const K = H(S)

      // M = H(H(N) xor H(g), H(I), s, A, B, K)
      // const M = H(H(N).xor(H(g)), H(I), s, A, B, K)

      const M = calculateSecretEvidence(A, B, S, s, I)

      return {
        key: K.toHex(),
        proof: M.toHex(),
        secret: S.toHex()
      }
    },

    calculateSecretEvidence,

    calculateS,

    calculateU,

    verifySession: (clientPublicEphemeral, clientSession, serverSessionProof) => {
      // H()    One-way hash function
      const { H, PAD } = params

      // A      Public ephemeral values
      // M      Proof of K
      // K      Shared, strong session key
      const A = SRPInteger.fromHex(clientPublicEphemeral)
      const M = SRPInteger.fromHex(clientSession.proof)
      const S = SRPInteger.fromHex(clientSession.secret)

      // H(A, M, K)
      // TODO for compatibility with server implementation use following formula for M2 calculation
      const expected = H(PAD(A), PAD(M), PAD(S))
      const actual = SRPInteger.fromHex(serverSessionProof)

      if (!actual.equals(expected)) {
        // fixme: .code, .statusCode, etc.
        throw new Error('Server provided session proof is invalid')
      } else {
        console.log('OK - server session proved')
      }
    }
  }
}
