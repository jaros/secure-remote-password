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

const withoutLeadingZeros = hexString => new BigInteger(hexString, 16).toString(16)

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

  test('login', async () => {
    const stepZero = await api.post('/auth/session', {}, {
      headers: {
        Accept: '*/*'
      },
      params: {
        login: username
      }
    })
    const sessionId = stepZero.data

    const stepOne = await api.post('/auth/challenge', {}, {
      params: {sessionId}
    })
    const challenge = stepOne.data
    console.log(challenge)

    const privateKey = client1024Bit.derivePrivateKey(challenge.s, username, password) // x

    const clientEphemeral = client1024Bit.generateEphemeral() // A and a
    console.log('client Aa', clientEphemeral)

    const stepTwo = await api.post('/auth/challenge/a', {}, {
      params: {
        A: SRPInteger.fromHex(clientEphemeral.public).toString(),
        sessionId
      }
    })

    const serverEphemeralPublic = SRPInteger.fromDecimal(stepTwo.data.B)

    console.log('got server public B', serverEphemeralPublic.toString())

    const clientSession = client1024Bit.deriveSession(clientEphemeral.secret, serverEphemeralPublic.toHex(), challenge.s, username, privateKey)
// try to calculate M1 in a simple way like in bouncycastle lib
    const M1 = SRPInteger.fromHex(clientSession.proof).toString()

    const stepThree = await api.post('/auth/challenge/m', {}, {
      params: {
        M1,
        sessionId
      }
    })

    const serverProof = stepThree.data.M2
    console.log('M2:', serverProof)
    // client.verifySession(clientEphemeral.public, clientSession, serverSession.proof)
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
    expect(kHex).toBe('1a1a4c140cde70ae360c1ec33a33155b1022df951732a476a862eb3ab8206a5c')
  })

  test('calculate x at 1024-bit group', () => {
    let params = client1024Bit.params()
    console.log(params.N.toString())
    console.log(params.g.toString())

    let expectedX = '65ac38dff8bc34ae0f259e91fbd0f4ca2fa43081c9050cec7cac20d015f303'

    let I = 'alice'
    let P = 'password123'
    let s = 'BEB25379D1A8581EB5A727673A2441EE'

    const xHex = client1024Bit.derivePrivateKey(s, I, P)

    console.log('calculated x', xHex)
    expect(withoutLeadingZeros(xHex)).toBe(expectedX)
  })

  test('calculate verifier at 1024-bit group', () => {
    let params = client1024Bit.params()
    console.log(params.N.toString())
    console.log(params.g.toString())

    let expectedV = '27e2855ac715f625981dba238667955db341a3bdd919868943bc049736c7804cd8e0507dfefbf5b8573f5aae7bac19b257034254119ab520e1f7cf3f45d01b159016847201d14c8dc95ec34e8b26ee255bc4cb28d4f97e0db97b65bdd196c4d2951cd84f493afd7b34b90984357988601a3643358b81689dfd0cb0d21e21cf6e'

    let I = 'alice'
    let P = 'password123'
    let s = 'BEB25379D1A8581EB5A727673A2441EE'

    const verifier = client1024Bit.deriveVerifier(client1024Bit.derivePrivateKey(s, I, P))

    console.log('calculated verifier', verifier)
    expect(withoutLeadingZeros(verifier)).toBe(expectedV)
  })

  test('calculate k param at 2048-bit group', () => {
    const params = client2048Bit.params()
    console.log(params.N.toString())
    console.log(params.g.toString())
    const kHex = params.k.toHex()
    expect(withoutLeadingZeros(kHex)).toBe('5b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300')
  })
})
