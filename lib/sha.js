'use strict'

const sjcl = require('./sjcl')

const SRPInteger = require('./srp-integer')

/**
 * @param hashFunctionName
 */
module.exports = (hashFunctionName) =>
  /**
   * @param {(string | SRPInteger)[]} args
   */
    (...args) => {
      const Hash = sjcl.hash[hashFunctionName]
      if (!Hash) {
        throw new ReferenceError(hashFunctionName + ' is not supported [' + Object.keys(sjcl.hash) + ']')
      }
      const h = new Hash() // 'sha256'

      for (const arg of args) {
        if (arg instanceof SRPInteger) {
          h.update(sjcl.codec.hex.toBits(arg.toHex()))
        } else if (typeof arg === 'string') {
          h.update(arg)
        } else {
          throw new TypeError('Expected string or SRPInteger')
        }
      }

      return SRPInteger.fromHex(sjcl.codec.hex.fromBits(h.finalize()))
    }
