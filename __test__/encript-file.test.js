/* eslint-disable new-cap */
/* eslint-env jest */

const forge = require('node-forge')
// forge.options.usePureJavaScript = true

describe('RSA encryption', () => {

  test('sha1 encrypt', () => {
    const h = forge.md.sha1.create()
    h.update('abc')
    const res = h.digest().toHex()
    expect(res).toBe('a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d'.replace(/\s+/g, ''))
  })

  test('sha1 encrypt 2', () => {
    const h = forge.md.sha1.create()
    h.update('')
    const res = h.digest().toHex()
    expect(res).toBe('da39a3ee 5e6b4b0d 3255bfef 95601890 afd80709'.replace(/\s+/g, ''))
  })

  test('encrypt with forge', () => {
    // generate a random key and IV for AES-256 bit
    let key = forge.random.getBytesSync(32) // bytes
    let iv = forge.random.getBytesSync(32) // bytes

    let someBytes = 'hello world' // or file bytes here

// encrypt some bytes
    let cipher = forge.cipher.createCipher('AES-CBC', key)
    cipher.start({iv: iv})
    cipher.update(forge.util.createBuffer(someBytes)) // put file here
    cipher.finish()
    let encrypted = cipher.output
// outputs encrypted hex
    console.log(encrypted.toHex())
  })

  test('generate RSA', () => {
    const {pki, util, asn1} = forge

    let keypair = pki.rsa.generateKeyPair({bits: 1024, e: 0x10001})

    const hexPublicKey = asn1.toDer(pki.publicKeyToAsn1(keypair.publicKey)).toHex()
    console.log('hex pub key: ', hexPublicKey)

    const pubKey = pki.publicKeyFromAsn1(asn1.fromDer(util.createBuffer(util.binary.hex.decode(hexPublicKey))))

    const hexPrivateKey = asn1.toDer(pki.privateKeyToAsn1(keypair.privateKey)).toHex()
    console.log('hex priv key: ', hexPrivateKey)
    const privKey = pki.privateKeyFromAsn1(asn1.fromDer(util.createBuffer(util.binary.hex.decode(hexPrivateKey))))

    let encrypted = pubKey.encrypt('test')
    console.log('encrypted', util.binary.hex.encode(encrypted))
    //
    let decrypted = privKey.decrypt(encrypted)
    console.log('decrypted', decrypted)
  })

  const hexPublic = '30819f300d06092a864886f70d010101050003818d003081890281810091f93d8fbd2399013cc7ccfe57c1e74223a93cdd29e4156ff9a434bfc7f3ce5f6ab3b7b3e1d198037309e3237095b3e9924f5e549c64bf2e9c4ff1537d4979709ee9f239d1376a0f765d651a6e19265be8441613a57d19bf269baa36ed37639cd5c3fa8c6244652c761f81c44b1ebc0cc8e79937fce596f1d3586aada056f2530203010001'
  const hexPrivate = '3082025c0201000281810091f93d8fbd2399013cc7ccfe57c1e74223a93cdd29e4156ff9a434bfc7f3ce5f6ab3b7b3e1d198037309e3237095b3e9924f5e549c64bf2e9c4ff1537d4979709ee9f239d1376a0f765d651a6e19265be8441613a57d19bf269baa36ed37639cd5c3fa8c6244652c761f81c44b1ebc0cc8e79937fce596f1d3586aada056f25302030100010281800fed814120e3347bc5150c1228a338c7a7ba7cb0a93480fe51e00ffd6924fa3cc118d10fa8b1450403566dd95d1c88a010dde62e174e8ae9dc1680ff9a291d3df96f005875f13a8f2e9524e0cd2dd1d7497ed84f342965de1cb3049f634e75bc6e3bab5974118cc9a33bcd68f13e179ce6454302353ff0a4e34752c5536e09e1024100c9f118c0e7c76ba29b36165a238b9ef8007e7cce6f6642c2477f462dab1921a75b56ca5e23c05c5eb33b6cfbf883fc26b3cf2958b28ca447619c8cc812c32111024100b90cb0ae34e0a2cce67454bb46fc8a9bbd73d7212e311d879be017e99d44b4575ab4718baa456d3fe36aa9c087e882b7deacc76269e198e3397c5b74fe429d2302404494d5b445c2eb220916405712754b62ac4048c08f02aaaf723a9e29ca4eb9a82d93f71c2b861b98a9c407ca36e7140e4cc89121275a2e3c73c107eab6bc801102410097427a414bd3baff85f8dd31e00a9a3a479822e76a5c9768bbcf677c7c2326cea8c40a7441905287009bb57a3d1d9f8c30a646ac792400d6ebac6d0daab044c502406fc926d3a0cae596af770d02591f832649f9c50c587729c6281b1280a1e1c78c04d9e9bc60c542373c16a606b6fce035350dbd2d49be2d804728cd4f466d6153'

  test('reuse RSA', () => {
    const {pki, util, asn1} = forge

    const pubKey = pki.publicKeyFromAsn1(asn1.fromDer(util.createBuffer(util.binary.hex.decode(hexPublic))))

    const encrypted = pubKey.encrypt('home_ho')
    console.log('encrypted home_ho', encrypted)

    const privKey = pki.privateKeyFromAsn1(asn1.fromDer(util.createBuffer(util.binary.hex.decode(hexPrivate))))

    const decrypted = privKey.decrypt(encrypted)
    console.log(decrypted)
  })
})
