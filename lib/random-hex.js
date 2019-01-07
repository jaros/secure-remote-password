const CryptoJS = require('crypto-js')

let wordArray = CryptoJS.lib.WordArray.create()

// generate a random salt that should be stored with the user verifier
// client.generateRandomSalt() - requires nodejs 'crypto' module that is not available in react-native
// use another way to generate salt
module.exports = function randomHex (hexLength) {
  return wordArray.random(hexLength || 32).toString()
}
