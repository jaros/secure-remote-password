/* eslint-env jest */
const apisauce = require('apisauce')

const SRPInteger = require('../lib/srp-integer')
const clientBase = require('../client')
const client1024Bit = clientBase.init('1024-bit')
const client2048Bit = clientBase.init('default')

const { BigInteger } = require('jsbn')

const api = apisauce.create({
  baseURL: 'http://localhost:8080',
  timeout: 40000
})

jest.setTimeout(45000)

describe('call api', () => {
  const srpClient = client1024Bit
  const username = 'jaros@github.com'
  const password = '$uper$imple'

  test('signup', async () => {
    const salt = srpClient.generateSalt()
    const privateKey = srpClient.derivePrivateKey(salt, username, password)
    const verifier = SRPInteger.fromHex(srpClient.deriveVerifier(privateKey)).toString()
    const challenge = {
      'id': username,
      's': salt,
      'g': srpClient.params().g.toString(),
      'N': srpClient.params().N.toString(),
      'v': verifier
    }
    console.log(challenge)
    expect(challenge.id).toBe(username)
    expect(api).toBeDefined()
    const res = await api.post('/signup', challenge)
    console.log(res)
    expect(res).toBeDefined()
  })

  test('ping server', async () => {
    const res = await api.get('/ping')
    console.log(res)
  })
})

describe('test params', () => {
  test('calculate k param at 1024-bit group', () => {
    let params = client1024Bit.params()
    console.log(params.N.toString())
    console.log(params.g.toString())
    const kHex = params.k.toHex()
    console.log(kHex)
    const kBi = new BigInteger(kHex, 16)
    console.log(kBi.toString(16))
    expect(kBi.toString(16)).toBe('1a1a4c140cde70ae360c1ec33a33155b1022df951732a476a862eb3ab8206a5c')
  })

  test('calculate x param at 1024-bit group', () => {
    let params = client1024Bit.params()
    console.log(params.N.toString())
    console.log(params.g.toString())

    let expectedX = '65ac38dff8bc34ae0f259e91fbd0f4ca2fa43081c9050cec7cac20d015f303'

    let I = 'alice'
    let P = 'password123'
    let s = 'BEB25379D1A8581EB5A727673A2441EE'

    const xHex = client1024Bit.derivePrivateKey(s, I, P)

    console.log('calculated x', xHex)

    expect(xHex).toBe(expectedX)
  })

  test('calculate k param at 2048-bit group', () => {
    const params = client2048Bit.params()
    console.log(params.N.toString())
    console.log(params.g.toString())
    const kHex = params.k.toHex()
    console.log(kHex)
    const kBi = new BigInteger(kHex, 16)
    console.log(kBi.toString(16))
    expect(kBi.toString(16)).toBe('5b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300')
  })
})
