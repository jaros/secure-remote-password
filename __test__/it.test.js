/* eslint-env jest */
const apisauce = require('apisauce')

const randomHex = require('../lib/random-hex')

const SRPInteger = require('../lib/srp-integer')
const clientBase = require('../client')

const { BigInteger } = require('jsbn')

const api = apisauce.create({
  baseURL: 'http://localhost:8080',
  timeout: 40000
})

const withoutLeadingZeros = hexString => new BigInteger(hexString, 16).toString(16)

jest.setTimeout(45000)

describe('call api', () => {
  const srpClient = clientBase.init('1024-bit')
  const username = 'homer@github.com'
  const password = 'homer$uper$imple'

  test('signup', async () => {
    const salt = srpClient.generateSalt()
    const privateKey = srpClient.derivePrivateKey(salt, username, password)
    const verifier = srpClient.deriveVerifier(privateKey)
    const challenge = {
      'id': username,
      's': salt,
      'g': srpClient.params().g.toHex(),
      'N': srpClient.params().N.toHex(),
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
    const sessionId = stepZero.data.sessionId

    const stepOne = await api.post('/auth/challenge', {
      sessionId
    })
    const challenge = stepOne.data
    console.log(challenge)

    // init client corresponding to challenge data
    const client = clientBase.init({
      hashFunction: 'sha256',
      generatorModulo: challenge.g,
      largeSafePrime: challenge.N
    })

    const privateKey = client.derivePrivateKey(challenge.s, username, password) // x

    const clientEphemeral = client.generateEphemeral() // A and a
    console.log('client Aa', clientEphemeral)
    const A = clientEphemeral.public

    const stepTwo = await api.post('/auth/challenge/a', {
      A,
      sessionId
    })

    const serverEphemeralPublic = SRPInteger.fromHex(stepTwo.data.B)

    console.log('got server public B', stepTwo.data.B)

    const clientSession = client.deriveSession(clientEphemeral.secret, serverEphemeralPublic.toHex(), challenge.s, username, privateKey)
// try to calculate M1 in a simple way like in bouncycastle lib
    const M1 = clientSession.proof

    console.log('sending secret proof M1', M1)
    const stepThree = await api.post('/auth/challenge/m', {
      M1,
      sessionId
    })

    const serverProof = stepThree.data.M2
    console.log('M2:', serverProof)
    client.verifySession(clientEphemeral.public, clientSession, serverProof)
  })
})

describe('test params', () => {
  const client1024Bit = clientBase.init({
    largeSafePrime: `
    EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C
    9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4
    8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29
    7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A
    FD5138FE 8376435B 9FC61D2F C0EB06E3
  `,
    generatorModulo: '2',
    hashFunction: 'sha256'
  })

  test('random hex', () => {
    console.log(randomHex())
    console.log(randomHex((256)))
    console.log(randomHex((256 / 8)))
  })

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

  test('calculate A from a at 1024-bit group', () => {
    let a = '60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393'
    let expectedA = '61d5e490f6f1b79547b0704c436f523dd0e560f0c64115bb72557ec44352e8903211c04692272d8b2d1a5358a2cf1b6e0bfcf99f921530ec8e39356179eae45e42ba92aeaced825171e1e8b9af6d9c03e1327f44be087ef06530e69f66615261eef54073ca11cf5858f0edfdfe15efeab349ef5d76988a3672fac47b0769447b'

    const A = client1024Bit.deriveEphemeralPublicKey(SRPInteger.fromHex(a)).toHex()

    console.log('calculated A', A)
    expect(withoutLeadingZeros(A)).toBe(expectedA)
  })

  test('calculate u from A and B at 1024-bit group', () => {
    let A = SRPInteger.fromHex('61d5e490f6f1b79547b0704c436f523dd0e560f0c64115bb72557ec44352e8903211c04692272d8b2d1a5358a2cf1b6e0bfcf99f921530ec8e39356179eae45e42ba92aeaced825171e1e8b9af6d9c03e1327f44be087ef06530e69f66615261eef54073ca11cf5858f0edfdfe15efeab349ef5d76988a3672fac47b0769447b')
    let B = SRPInteger.fromHex('bd0c61512c692c0cb6d041fa01bb152d4916a1e77af46ae105393011baf38964dc46a0670dd125b95a981652236f99d9b681cbf87837ec996c6da04453728610d0c6ddb58b318885d7d82c7f8deb75ce7bd4fbaa37089e6f9c6059f388838e7a00030b331eb76840910440b1b27aaeaeeb4012b7d7665238a8e3fb004b117b58')
    let expectedU = 'e23c86988192822d7a1fb2648214b65ac406882840d10295d77afeeda469a7f5'

    const u = client1024Bit.calculateU(A, B).toHex()

    console.log('calculated u', u)
    expect(withoutLeadingZeros(u)).toBe(expectedU)
  })

  test('calculate secret S at 1024-bit group', () => {
    let a = SRPInteger.fromHex('60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393')
    let x = SRPInteger.fromHex('65ac38dff8bc34ae0f259e91fbd0f4ca2fa43081c9050cec7cac20d015f303')
    let u = SRPInteger.fromHex('e23c86988192822d7a1fb2648214b65ac406882840d10295d77afeeda469a7f5')
    let B = SRPInteger.fromHex('bd0c61512c692c0cb6d041fa01bb152d4916a1e77af46ae105393011baf38964dc46a0670dd125b95a981652236f99d9b681cbf87837ec996c6da04453728610d0c6ddb58b318885d7d82c7f8deb75ce7bd4fbaa37089e6f9c6059f388838e7a00030b331eb76840910440b1b27aaeaeeb4012b7d7665238a8e3fb004b117b58')
    let expectedS = '810f04455dec662a6697958c59d724af8a4021aff8be89935c2501b3d52ea8b86e6a8cda3dd5d2a2b24942ca29e97203e6419f83250ce66c270a6f88009eb3c894d2aa6a12f633aa10f0a1b80c347439db39bd239a6e9cfc1902136258f7898739a14bcddb162cc42b1ac216f39606ca35703b757f2da38cfd77541c4bb74388'

    const s = client1024Bit.calculateS(B, a, u, x).toHex()

    console.log('calculated s', s)
    expect(withoutLeadingZeros(s)).toBe(expectedS)
  })

  test('calculate k param at 2048-bit group', () => {
    const client2048Bit = clientBase.init('default')
    const params = client2048Bit.params()
    console.log(params.N.toString())
    console.log(params.g.toString())
    const kHex = params.k.toHex()
    expect(withoutLeadingZeros(kHex)).toBe('5b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300')
  })
})
