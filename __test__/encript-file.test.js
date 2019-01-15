/* eslint-disable new-cap */
/* eslint-env jest */

const forge = require('node-forge')
forge.options.usePureJavaScript = true

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
    // generate a random key and IV
    let key = forge.random.getBytesSync(16)
    let iv = forge.random.getBytesSync(8)

    let someBytes = 'hello world'

// encrypt some bytes
    var cipher = forge.rc2.createEncryptionCipher(key)
    cipher.start(iv)
    cipher.update(forge.util.createBuffer(someBytes))
    cipher.finish()
    var encrypted = cipher.output
// outputs encrypted hex
    console.log(encrypted.toHex())

// decrypt some bytes
//     var cipher = forge.rc2.createDecryptionCipher(key)
//     cipher.start(iv)
//     cipher.update(encrypted)
//     cipher.finish()
// // outputs decrypted hex
//     console.log(cipher.output.toHex())
  })
})
