'use strict'

const hashFun = require('./sha')
const SRPInteger = require('./srp-integer')
const sjcl = require('./sjcl')

const group2048 = sjcl.keyexchange.srp.knownGroup('2048')
const bnTohex = bn => bn.toString().replace(/^0x/g, '')
const input2048Bit = {
  largeSafePrime: bnTohex(group2048.N),
  generatorModulo: bnTohex(group2048.g),
  hashFunction: 'sha256'
}

/**
 *
 * @param config is either config object that defines input params or the name of bit group that will provide preconfigured params
 * <p>
 * bit group name can be '1024-bit', '2048-bit' and 'default' that falls back to '2048-bit'
 * @returns {{N: SRPInteger, g: SRPInteger, k: *, H: *, PAD: (function(SRPInteger): *), hashOutputBytes: number}}
 */
module.exports = function (config) {
  let input = input2048Bit
  if (typeof config === 'object') {
    input = config
  } else if (config === '1024-bit') {
    const group1024 = sjcl.keyexchange.srp.knownGroup('1024')
    input = {
      largeSafePrime: bnTohex(group1024.N),
      generatorModulo: bnTohex(group1024.g),
      hashFunction: 'sha256'
    }
  }

  // N      A large safe prime (N = 2q+1, where q is prime)
  // g      A generator modulo N
  // k      Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
  // H()    One-way hash function
  // PAD()  Pad the number to have the same number of bytes as N

  const N = SRPInteger.fromHex(input.largeSafePrime.replace(/\s+/g, ''))
  const paddedLength = N.length()

  /**
   * @param {SRPInteger} integer
   */
  const PAD = (integer) => integer.pad(paddedLength)

  const g = SRPInteger.fromHex(input.generatorModulo.replace(/\s+/g, ''))
  const H = hashFun(input.hashFunction)
  const k = H(N, PAD(g))

  return {
    N,
    g,
    k,
    H,
    PAD,
    hashOutputBytes: (256 / 8)
  }
}
