'use strict'

const crypto = require('crypto')

const SRPInteger = require('./srp-integer')

/**
 * @param hashFunctionName
 */
module.exports = (hashFunctionName) =>
  /**
   * @param {(string | SRPInteger)[]} args
   */
    (...args) => {
      const h = crypto.createHash(hashFunctionName) // 'sha256'

      for (const arg of args) {
        if (arg instanceof SRPInteger) {
          h.update(Buffer.from(arg.toHex(), 'hex'))
        } else if (typeof arg === 'string') {
          h.update(arg)
        } else {
          throw new TypeError('Expected string or SRPInteger')
        }
      }

      return SRPInteger.fromHex(h.digest('hex'))
    }
