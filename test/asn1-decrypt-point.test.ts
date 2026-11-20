import { kdf, sm2, sm3 } from '@/index'
import { encodeEnc } from '@/sm2/asn1'
import { beforeAll, describe, expect, it } from 'vitest'

beforeAll(async () => {
  await sm2.initRNGPool()
})

describe('SM2 ASN.1 ciphertext C1 validation', () => {
  it.each([0, 1])('rejects an off-curve C1 in cipher mode %s', cipherMode => {
    const pair = sm2.generateKeyPairHex()
    const ciphertext = encodeEnc(1n, 1n, '00'.repeat(32), '00'.repeat(16))
    expect(() => sm2.doDecrypt(ciphertext, pair.privateKey, cipherMode, { asn1: true })).toThrow(/bad point/)
  })

  it('rejects a zero-point ciphertext with a valid planted plaintext and hash', () => {
    const message = Uint8Array.from([0x61, 0x62, 0x63])
    const stream = kdf(new Uint8Array(64), message.length)
    const encrypted = message.map((byte, index) => byte ^ stream[index])
    const ciphertextHex = sm2.arrayToHex(Array.from(encrypted))
    const hashInput = new Uint8Array(64 + message.length)
    hashInput.set(message, 32)
    const hash = sm3(hashInput)
    for (const cipherMode of [0, 1]) {
      const ciphertext = cipherMode === 1
        ? encodeEnc(0n, 0n, hash, ciphertextHex)
        : encodeEnc(0n, 0n, ciphertextHex, hash)
      for (const scalar of ['1', '2', '2b']) {
        const privateKey = scalar.padStart(64, '0')
        expect(() => sm2.doDecrypt(ciphertext, privateKey, cipherMode, { asn1: true })).toThrow(/bad point/)
      }
    }
  })

  it.each([0, 1])('decrypts valid ASN.1 ciphertext in cipher mode %s', cipherMode => {
    const pair = sm2.generateKeyPairHex()
    const message = 'valid ASN.1 ciphertext control'
    const ciphertext = sm2.doEncrypt(message, pair.publicKey, cipherMode, { asn1: true })
    expect(sm2.doDecrypt(ciphertext, pair.privateKey, cipherMode, { asn1: true })).toBe(message)
    const bytes = sm2.doDecrypt(ciphertext, pair.privateKey, cipherMode, { asn1: true, output: 'array' })
    expect(sm2.arrayToUtf8(bytes)).toBe(message)
  })
})
