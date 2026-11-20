import { sm2 } from '@/index'
import { sm2Curve } from '@/sm2/ec'
import { beforeAll, describe, expect, it } from 'vitest'

const order = sm2Curve.CURVE.n
const knownPrivateKey = '1'.padStart(64, '0')

beforeAll(async () => {
  await sm2.initRNGPool()
})

describe('SM2 caller-supplied key generation input', () => {
  it.each([
    ['0', 1n],
    ['42', 43n],
    ['0x2a', 43n],
    ['123123123123123', 123123123123124n],
    ['9007199254740993', 9007199254740994n],
    [(order - 2n).toString(), order - 1n],
    [(order - 1n).toString(), 1n],
    [order.toString(), 2n],
    [(order * 3n + 42n).toString(), 46n],
    ['-1', order - 1n],
  ])('maps input %s to the expected scalar', (seed, scalar) => {
    const pair = sm2.generateKeyPairHex(seed)
    expect(pair.privateKey).toBe(scalar.toString(16).padStart(64, '0'))
    expect(pair.publicKey).toBe(sm2.getPublicKeyFromPrivateKey(pair.privateKey))
  })

  it('produces deterministic, distinct pairs for distinct small inputs', () => {
    const seeds = ['7', '42', '31337', '123123123123123', '999999999999999999999999999999']
    const pairs = seeds.map(seed => sm2.generateKeyPairHex(seed))
    expect(new Set(pairs.map(pair => pair.privateKey)).size).toBe(seeds.length)
    expect(new Set(pairs.map(pair => pair.publicKey)).size).toBe(seeds.length)
    expect(pairs).toEqual(seeds.map(seed => sm2.generateKeyPairHex(seed)))
  })

  it('prevents the constant private key from signing or decrypting for other seed keys', () => {
    const pair = sm2.generateKeyPairHex('42')
    const message = 'seeded key security control'
    const forged = sm2.doSignature(message, knownPrivateKey)
    expect(sm2.doVerifySignature(message, forged, pair.publicKey)).toBe(false)
    const signature = sm2.doSignature(message, pair.privateKey)
    expect(sm2.doVerifySignature(message, signature, pair.publicKey)).toBe(true)
    const ciphertext = sm2.doEncrypt(message, pair.publicKey)
    expect(sm2.doDecrypt(ciphertext, knownPrivateKey)).not.toBe(message)
    expect(sm2.doDecrypt(ciphertext, pair.privateKey)).toBe(message)
  })

  it('keeps unseeded generation random and usable', () => {
    const first = sm2.generateKeyPairHex()
    const second = sm2.generateKeyPairHex()
    expect(first.privateKey).not.toBe(second.privateKey)
    const signature = sm2.doSignature('random key control', first.privateKey)
    expect(sm2.doVerifySignature('random key control', signature, first.publicKey)).toBe(true)
  })
})
