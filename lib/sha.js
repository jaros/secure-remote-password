'use strict'
const forge = require('node-forge')
forge.options.usePureJavaScript = true
const SRPInteger = require('./srp-integer')

/**
 * @param hashFunctionName
 */
module.exports = (hashFunctionName) =>
  /**
   * @param {(string | SRPInteger)[]} args
   */
    (...args) => {
      const hash = forge.md[hashFunctionName]

      if (!hash) {
        throw new ReferenceError(hashFunctionName + ' is not supported [' + Object.keys(forge.md) + ']')
      }
      const h = hash.create() // 'sha256'

      for (const arg of args) {
        if (arg instanceof SRPInteger) {
          let bytes = forge.util.binary.hex.decode(arg.toHex())
          let buffer = forge.util.createBuffer(bytes, 'raw')
          h.update(buffer.getBytes())
        } else if (typeof arg === 'string') {
          h.update(arg)
        } else {
          throw new TypeError('Expected string or SRPInteger')
        }
      }

      return SRPInteger.fromHex(h.digest().toHex())
    }
