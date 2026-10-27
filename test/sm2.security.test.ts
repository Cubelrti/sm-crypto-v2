import { sm2 } from '@/index'
import { hexToArray } from '@/sm2'
import { describe, expect, it } from 'vitest'

// GB/T 32918.5-2017, Appendix A.2, example 1.
const privateKey = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8'
const publicKey = '0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13'
const signature = 'f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa'
// Historical low-level result for the same message, key and nonce without hashing.
const legacySignature = '04ebfc718e8d1798620432268e77feb6415e9c43817a9d76b4847336957a0de711c0a451ba212c7061f513d1c8963402575d8ca8f06cdea4a554083e8e6458f6'
const message = 'message digest'
function pointPool() {
  return [{
    k: BigInt('0x59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21'),
    x1: BigInt('0x04ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73'),
  }]
}

describe('SM2 standard signatures and upstream compatibility', () => {
  it('signs and verifies the standard vector with explicit hash:true', () => {
    expect(sm2.doSignature(message, privateKey, { pointPool: pointPool(), hash: true })).toBe(signature)
    expect(sm2.doVerifySignature(message, signature, publicKey, { hash: true })).toBe(true)
    expect(sm2.doVerifySignature(message, signature, publicKey, { hash: false })).toBe(false)
    expect(sm2.doVerifySignature(message, signature, publicKey)).toBe(false)
  })

  it('preserves the historical default and explicit hash:false results', () => {
    for (const options of [{}, { hash: undefined }, { hash: false }]) {
      expect(sm2.doSignature(message, privateKey, { ...options, pointPool: pointPool() })).toBe(legacySignature)
      expect(sm2.doVerifySignature(message, legacySignature, publicKey, options)).toBe(true)
    }
    expect(sm2.doVerifySignature(message, legacySignature, publicKey, { hash: true })).toBe(false)
  })

  it('supports standard signatures with byte arrays, DER and compressed public keys', () => {
    const bytes = hexToArray('6d65737361676520646967657374')
    const compressed = sm2.compressPublicKeyHex(publicKey)
    expect(sm2.doSignature(bytes, privateKey, { pointPool: pointPool(), publicKey: compressed, hash: true })).toBe(signature)
    const der = sm2.doSignature(bytes, privateKey, { pointPool: pointPool(), der: true, hash: true })
    expect(sm2.doVerifySignature(bytes, der, compressed, { der: true, hash: true })).toBe(true)
  })

  it('binds hash:true signatures to the message and user identity', () => {
    expect(sm2.doVerifySignature('different message', signature, publicKey, { hash: true })).toBe(false)
    expect(sm2.doVerifySignature(message, signature, publicKey, { userId: 'another user', hash: true })).toBe(false)
    const signed = sm2.doSignature(message, privateKey, { userId: 'alice', hash: true })
    expect(sm2.doVerifySignature(message, signed, publicKey, { userId: 'alice', hash: true })).toBe(true)
    expect(sm2.doVerifySignature(message, signed, publicKey, { hash: true })).toBe(false)
  })

  it('distinguishes messages with leading zero bytes when hash:true', () => {
    const original = Uint8Array.of(1)
    const changed = Uint8Array.of(0, 1)
    const signed = sm2.doSignature(original, privateKey, { hash: true })
    expect(sm2.doVerifySignature(original, signed, publicKey, { hash: true })).toBe(true)
    expect(sm2.doVerifySignature(changed, signed, publicKey, { hash: true })).toBe(false)
  })

  it('supports empty messages when hash:true', () => {
    const signed = sm2.doSignature('', privateKey, { hash: true })
    expect(sm2.doVerifySignature('', signed, publicKey, { hash: true })).toBe(true)
    expect(sm2.doVerifySignature(new Uint8Array(), signed, publicKey, { hash: true })).toBe(true)
  })

  it('preserves explicit hash:false for precomputed digests and legacy signatures', () => {
    const digest = hexToArray(sm2.getHash('6d65737361676520646967657374', publicKey))
    expect(sm2.doSignature(digest, privateKey, { hash: false, pointPool: pointPool() })).toBe(signature)
    expect(sm2.doVerifySignature(digest, signature, publicKey, { hash: false })).toBe(true)
    const legacy = sm2.doSignature(message, privateKey, { hash: false })
    expect(sm2.doVerifySignature(message, legacy, publicKey, { hash: false })).toBe(true)
    expect(sm2.doVerifySignature(message, legacy, publicKey)).toBe(true)
  })
})
