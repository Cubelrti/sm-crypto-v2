import { sm4 } from '@/index'
import { hexToArray } from '@/sm2'
import { describe, expect, it } from 'vitest'

const key = '0123456789abcdeffedcba9876543210'
const iv = '00001234567800000000abcd'
// RFC 8998, Appendix A.1.
const plaintext = 'aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccddddddddddddddddeeeeeeeeeeeeeeeeffffffffffffffffeeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa'
const ciphertext = '17f399f08c67d5ee19d0dc9969c4bb7d5fd46fd3756489069157b282bb200735d82710ca5c22f0ccfa7cbf93d496ac15a56834cbcf98c397b4024a2691233b8d'
const associatedData = 'feedfacedeadbeeffeedfacedeadbeefabaddad2'
const tag = '83de3541e4c2b58177e065a9bf7b62ec'

describe('SM4 security requirements', () => {
  for (const mode of ['cbc', 'gcm'] as const) {
    it(`${mode} requires an explicit IV for encryption and decryption`, () => {
      expect(() => sm4.encrypt('message', key, { mode })).toThrow('iv is required')
      expect(() => sm4.decrypt(ciphertext, key, { mode, tag })).toThrow('iv is required')
      expect(() => sm4.encrypt('message', key, { mode, iv: undefined })).toThrow('iv is required')
    })

    it(`${mode} rejects empty or malformed hexadecimal IVs`, () => {
      for (const invalidIv of ['', new Uint8Array(), '0'.repeat(31), 'gg'.repeat(16)]) {
        expect(() => sm4.encrypt('message', key, { mode, iv: invalidIv })).toThrow('iv is invalid')
        expect(() => sm4.decrypt(ciphertext, key, { mode, iv: invalidIv, tag })).toThrow('iv is invalid')
      }
    })
  }

  it('CBC requires a 16-byte IV', () => {
    for (const length of [1, 12, 15, 17]) {
      expect(() => sm4.encrypt('message', key, { mode: 'cbc', iv: new Uint8Array(length) })).toThrow('iv is invalid')
    }
  })

  it('GCM validates the SM4 key in both directions', () => {
    for (const invalidKey of ['', new Uint8Array(15), new Uint8Array(17), '0'.repeat(31), 'zz'.repeat(16)]) {
      expect(() => sm4.encrypt('message', invalidKey, { mode: 'gcm', iv })).toThrow('key is invalid')
      expect(() => sm4.decrypt(ciphertext, invalidKey, { mode: 'gcm', iv, tag })).toThrow('key is invalid')
    }
  })

  it('GCM rejects missing, empty, truncated and oversized tags', () => {
    for (const invalidTag of [undefined, '', new Uint8Array(), tag.slice(0, -2), tag + '00', hexToArray(tag).slice(0, 15)]) {
      const options = { mode: 'gcm' as const, iv, associatedData, tag: invalidTag }
      expect(() => sm4.decrypt(ciphertext, key, options)).toThrow('GCM decryption requires a 16-byte authentication tag')
      expect(() => sm4.decrypt(ciphertext, key, { ...options, output: 'array' })).toThrow('GCM decryption requires a 16-byte authentication tag')
    }
  })

  it('GCM rejects malformed hexadecimal tags', () => {
    for (const invalidTag of ['gg' + tag.slice(2), tag.slice(1)]) {
      expect(() => sm4.decrypt(ciphertext, key, {
        mode: 'gcm', iv, associatedData, tag: invalidTag,
      })).toThrow('tag is invalid')
    }
  })

  it('GCM authenticates the ciphertext, AAD, nonce and tag', () => {
    const options = { mode: 'gcm' as const, iv, associatedData, tag }
    expect(() => sm4.decrypt('00' + ciphertext.slice(2), key, options)).toThrow('authentication tag mismatch')
    for (const changed of [
      { associatedData: '00' + associatedData.slice(2) },
      { iv: '01' + iv.slice(2) },
      { tag: '00' + tag.slice(2) },
    ]) {
      expect(() => sm4.decrypt(ciphertext, key, { ...options, ...changed })).toThrow('authentication tag mismatch')
    }
  })

  it('GCM always returns the tag for string and array encryption', () => {
    for (const outputTag of [undefined, false, true]) {
      const options = { mode: 'gcm' as const, iv, associatedData, outputTag }
      expect(sm4.encrypt(hexToArray(plaintext), key, options)).toEqual({ output: ciphertext, tag })
      expect(sm4.encrypt(hexToArray(plaintext), key, { ...options, output: 'array' })).toEqual({
        output: hexToArray(ciphertext), tag: hexToArray(tag),
      })
    }
  })

  it('GCM authenticates empty messages and partial blocks', () => {
    for (const message of ['', 'a', 'hello world', '12345678901234567']) {
      const encrypted = sm4.encrypt(message, key, { mode: 'gcm', iv })
      expect(sm4.decrypt(encrypted.output, key, { mode: 'gcm', iv, tag: encrypted.tag })).toBe(message)
      expect(() => sm4.decrypt(encrypted.output, key, { mode: 'gcm', iv })).toThrow('authentication tag')
    }
  })

  it('GCM uses inc32 for a non-96-bit IV when the counter wraps', () => {
    // Independently calculated using OpenSSL SM4-ECB and SP 800-38D GHASH.
    // This IV produces J0 = 00112233445566778899aabbfffffffe.
    const nonce = 'e2183b1a42f8a048a631e31d6c8270d4'
    const message = hexToArray('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324')
    const aad = '000102030405060708090a0b0c0d0e0f101112'
    const output = '37f28ed7d38fd8ea282943afc06920cbc8444158bc3e3fe682815e06efc318f6f48b97c2ef'
    const authTag = '1241f9ca16898ed939c2d9011264ea85'
    expect(sm4.encrypt(message, key, { mode: 'gcm', iv: nonce, associatedData: aad })).toEqual({ output, tag: authTag })
    expect(sm4.decrypt(output, key, {
      mode: 'gcm', iv: nonce, associatedData: aad, tag: authTag, output: 'array',
    })).toEqual(message)
  })
})
