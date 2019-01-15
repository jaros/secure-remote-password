const forge = require('node-forge')
forge.options.usePureJavaScript = true


// generate a random salt that should be stored with the user verifier
// client.generateRandomSalt() - requires nodejs 'crypto' module that is not available in react-native
// use another way to generate salt
module.exports = function randomHex (hexLength) {
  let bytesSync = forge.random.createInstance().getBytesSync(hexLength || 32)
  const rndHex = forge.util.binary.hex.encode(bytesSync)
  console.log('bytesSync', rndHex)
  return rndHex
}
