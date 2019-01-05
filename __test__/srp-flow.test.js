/* eslint-env jest */

const client = require('../client').init('default')
const server = require('../server')
const SRPInteger = require('../lib/srp-integer')

describe('Secure Remote Password', () => {
  test('should authenticate a user', () => {
    const username = 'linus@folkdatorn.se'
    const password = '$uper$ecure'

    const salt = client.generateSalt()
    const privateKey = client.derivePrivateKey(salt, username, password)
    const verifier = client.deriveVerifier(privateKey)

    const clientEphemeral = client.generateEphemeral()
    const serverEphemeral = server.generateEphemeral(verifier)

    const clientSession = client.deriveSession(clientEphemeral.secret, serverEphemeral.public, salt, username, privateKey)
    const serverSession = server.deriveSession(serverEphemeral.secret, clientEphemeral.public, salt, username, verifier, clientSession.proof)

    client.verifySession(clientEphemeral.public, clientSession, serverSession.proof)

    expect(clientSession.key).toBe(serverSession.key)
  })
})

describe('SRPInteger', () => {
  test('should keep padding when going back and forth', () => {
    expect(SRPInteger.fromHex('a').toHex()).toBe('a')
    expect(SRPInteger.fromHex('0a').toHex()).toBe('0a')
    expect(SRPInteger.fromHex('00a').toHex()).toBe('00a')
    expect(SRPInteger.fromHex('000a').toHex()).toBe('000a')
    expect(SRPInteger.fromHex('0000a').toHex()).toBe('0000a')
    expect(SRPInteger.fromHex('00000a').toHex()).toBe('00000a')
    expect(SRPInteger.fromHex('000000a').toHex()).toBe('000000a')
    expect(SRPInteger.fromHex('0000000a').toHex()).toBe('0000000a')
    expect(SRPInteger.fromHex('00000000a').toHex()).toBe('00000000a')
  })
})
