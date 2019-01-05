/* eslint-env mocha */

const assert = require('assert')

const client = require('./client')
const server = require('./server')
const SRPInteger = require('./lib/srp-integer')

const { BigInteger } = require('jsbn')
const paramsFun = require('./lib/params')
const params = paramsFun()

describe('test params', () => {
  it('calculate k param at 1024-bit group', () => {
    let params = paramsFun('1024-bit')
    console.log(params.N.toString())
    console.log(params.g.toString())
    const kHex = params.k.toHex()
    console.log(kHex)
    const kBi = new BigInteger(kHex, 16)
    console.log(kBi.toString(16))
    assert.strictEqual(kBi.toString(16), '1a1a4c140cde70ae360c1ec33a33155b1022df951732a476a862eb3ab8206a5c')
  })

  it('calculate k param at 2048-bit group', () => {
    console.log(params.N.toString())
    console.log(params.g.toString())
    const kHex = params.k.toHex()
    console.log(kHex)
    const kBi = new BigInteger(kHex, 16)
    console.log(kBi.toString(16))
    assert.strictEqual(kBi.toString(16), '5b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300')
  })
})

describe('Secure Remote Password', () => {
  it('should authenticate a user', () => {
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

    assert.strictEqual(clientSession.key, serverSession.key)
  })
})

describe('SRPInteger', () => {
  it('should keep padding when going back and forth', () => {
    assert.strictEqual(SRPInteger.fromHex('a').toHex(), 'a')
    assert.strictEqual(SRPInteger.fromHex('0a').toHex(), '0a')
    assert.strictEqual(SRPInteger.fromHex('00a').toHex(), '00a')
    assert.strictEqual(SRPInteger.fromHex('000a').toHex(), '000a')
    assert.strictEqual(SRPInteger.fromHex('0000a').toHex(), '0000a')
    assert.strictEqual(SRPInteger.fromHex('00000a').toHex(), '00000a')
    assert.strictEqual(SRPInteger.fromHex('000000a').toHex(), '000000a')
    assert.strictEqual(SRPInteger.fromHex('0000000a').toHex(), '0000000a')
    assert.strictEqual(SRPInteger.fromHex('00000000a').toHex(), '00000000a')
  })
})
