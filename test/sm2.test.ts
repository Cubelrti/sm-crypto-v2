import { sm2 } from '@/index'
import { arrayToHex, hexToArray } from '@/sm2'
import { expect, it, describe, beforeEach } from 'vitest'

const cipherMode = 1 // 1 - C1C3C2，0 - C1C2C3

// const msgString = 'abcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCDabcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCDabcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCDabcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCDabcdefghABCDEFGH';
const msgString = 'absasdagfadgadsfdfdsf'

declare module 'vitest' {
    export interface TestContext {
        privateKey: string
        compressedPublicKey: string
        unCompressedPublicKey: string
    }

}

beforeEach(async (context) => {
    // 生成密钥对
    let keypair = sm2.generateKeyPairHex()
    let unCompressedPublicKey = keypair.publicKey
    let privateKey = keypair.privateKey

    let compressedPublicKey = sm2.compressPublicKeyHex(unCompressedPublicKey)
    context.privateKey = privateKey
    context.compressedPublicKey = compressedPublicKey
    context.unCompressedPublicKey = unCompressedPublicKey
})

describe('sm2: generate keypair', () => {
    it('public key length should be correct', ({ privateKey, compressedPublicKey, unCompressedPublicKey }) => {
        expect(unCompressedPublicKey.length).toBe(130)
        expect(privateKey.length).toBe(64)
        expect(compressedPublicKey.length).toBe(66)
        expect(sm2.verifyPublicKey(unCompressedPublicKey)).toBe(true)
        expect(sm2.verifyPublicKey(compressedPublicKey)).toBe(true)
    })
    it('compressed public key should be equal', ({ compressedPublicKey, unCompressedPublicKey }) => {
        expect(sm2.comparePublicKeyHex(unCompressedPublicKey, compressedPublicKey)).toBe(true)
        expect(sm2.comparePublicKeyHex(unCompressedPublicKey, unCompressedPublicKey)).toBe(true)
        expect(sm2.comparePublicKeyHex(compressedPublicKey, compressedPublicKey)).toBe(true)
    })
    it('random generated different keypair', () => {
        const keypair1 = sm2.generateKeyPairHex()
        const keypair2 = sm2.generateKeyPairHex()
        console.log(keypair1, keypair2)
        expect(keypair1.privateKey === keypair2.privateKey).toBeFalsy()
        expect(keypair1.publicKey === keypair2.publicKey).toBeFalsy()
    })
    it('random generated keypair', () => {
        // 自定义随机数
        const random: number[] = []
        for (let i = 0; i < 20; i++) random.push(~~(Math.random() * 10))
        const keypair2 = sm2.generateKeyPairHex(random.join(''))
        expect(keypair2.publicKey.length).toBe(130)
        expect(keypair2.privateKey.length).toBe(64)
        const compressedPublicKey2 = sm2.compressPublicKeyHex(keypair2.publicKey)
        expect(compressedPublicKey2.length).toBe(66)
        expect(sm2.verifyPublicKey(keypair2.publicKey)).toBe(true)
        expect(sm2.verifyPublicKey(compressedPublicKey2)).toBe(true)
        expect(sm2.comparePublicKeyHex(keypair2.publicKey, compressedPublicKey2)).toBe(true)
    })
})

describe('sm2: encrypt and decrypt data', () => {
    it('decrypted data should be correct', ({ privateKey, compressedPublicKey, unCompressedPublicKey }) => {
        for (const publicKey of [unCompressedPublicKey, compressedPublicKey]) {
            let encryptData = sm2.doEncrypt(msgString, publicKey, cipherMode)
            let decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode)
            expect(decryptData).toBe(msgString)
        }
    })
    it('consistency within 10 times of encrypt and decrypt cycle', ({ unCompressedPublicKey, compressedPublicKey, privateKey }) => {
        for (const publicKey of [unCompressedPublicKey, compressedPublicKey]) {
            let encryptData = sm2.doEncrypt(msgString, publicKey, cipherMode)
            let decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode)
            for (let i = 0; i < 10; i++) {
                encryptData = sm2.doEncrypt(msgString, publicKey, cipherMode)
                decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode)
                expect(decryptData).toBe(msgString)
            }
        }
    });
    it('encrypt and decrypt with array input/output', ({ unCompressedPublicKey, compressedPublicKey, privateKey }) => {
        for (const publicKey of [unCompressedPublicKey, compressedPublicKey]) {

            let encryptData = sm2.doEncrypt(Uint8Array.from([0x61, 0x62, 0x73, 0x61, 0x73, 0x64, 0x61, 0x67, 0x66, 0x61, 0x64, 0x67, 0x61, 0x64, 0x73, 0x66, 0x64, 0x66, 0x64, 0x73, 0x66]), publicKey, cipherMode)
            let decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode)
            expect(decryptData).toBe(msgString)
            decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode, { output: 'array' })
            expect(decryptData).toEqual(Uint8Array.from([0x61, 0x62, 0x73, 0x61, 0x73, 0x64, 0x61, 0x67, 0x66, 0x61, 0x64, 0x67, 0x61, 0x64, 0x73, 0x66, 0x64, 0x66, 0x64, 0x73, 0x66]))
        }
    });
})


describe('sm2: encrypt and decrypt data using asn1 encoding', () => {
    it('decrypted data should be correct (non asn.1)', () => {
        const input = 'aabbccdd'
        const res = sm2.doEncrypt(hexToArray(input), '049812a275eca335e85998eb4030a6cc9e88a098010bdbfc134b26e29c43253439d3821ef18e69e0813bcc55eee7dc9163f1edb81ad2032b20cbdf1408897faaac', 1, {
            asn1: false,
        })
        // console.log('res', res)
        const dec = sm2.doDecrypt(res, '75b25a5d6101013e9be25816f81cf1f64bf78ea8383b32d61f5b26e6f1429e70', 1, {
            output: 'array',
            asn1: false,
        })
        expect(arrayToHex([...dec])).toBe(input)
    })
    it('decrypted data should be correct (asn.1)', () => {
        const input = 'aabbccdd'
        const res = sm2.doEncrypt(hexToArray(input), '049812a275eca335e85998eb4030a6cc9e88a098010bdbfc134b26e29c43253439d3821ef18e69e0813bcc55eee7dc9163f1edb81ad2032b20cbdf1408897faaac', 1, {
            asn1: true,
        })
        const dec = sm2.doDecrypt(res, '75b25a5d6101013e9be25816f81cf1f64bf78ea8383b32d61f5b26e6f1429e70', 1, {
            output: 'array',
            asn1: true,
        })
        expect(arrayToHex([...dec])).toBe(input)
        const input2 = 'xxxxx{"xx": "111","t": "1"}'
        const res2 = sm2.doEncrypt(input2, '049812a275eca335e85998eb4030a6cc9e88a098010bdbfc134b26e29c43253439d3821ef18e69e0813bcc55eee7dc9163f1edb81ad2032b20cbdf1408897faaac', 1, {
            asn1: true,
        })
        console.log(res2)
        const dec2 = sm2.doDecrypt(res2, '75b25a5d6101013e9be25816f81cf1f64bf78ea8383b32d61f5b26e6f1429e70', 1, {
            output: 'string',
            asn1: true,
        })
        expect(dec2).toBe(input2)
    })
    it('decrypted data should be correct: c1c2c3', () => {
        const input = 'aabbccdd'
        const res = sm2.doEncrypt(hexToArray(input), '049812a275eca335e85998eb4030a6cc9e88a098010bdbfc134b26e29c43253439d3821ef18e69e0813bcc55eee7dc9163f1edb81ad2032b20cbdf1408897faaac', 0, {
            asn1: true,
        })
        // console.log('res', res)
        const dec = sm2.doDecrypt(res, '75b25a5d6101013e9be25816f81cf1f64bf78ea8383b32d61f5b26e6f1429e70', 0, {
            output: 'array',
            asn1: true,
        })
        expect(arrayToHex([...dec])).toBe(input)
    })

})


describe('sm2: sign data and verify sign', () => {
    it('signature and generate ec point', ({ unCompressedPublicKey, compressedPublicKey, privateKey }) => {
        for (const publicKey of [unCompressedPublicKey, compressedPublicKey]) {
            // 纯签名 + 生成椭圆曲线点
            let sigValueHex = sm2.doSignature(msgString, privateKey)
            let verifyResult = sm2.doVerifySignature(msgString, sigValueHex, publicKey)
            expect(verifyResult).toBe(true)
        }
    })
    it('signature only', ({ unCompressedPublicKey, compressedPublicKey, privateKey }) => {
        for (const publicKey of [unCompressedPublicKey, compressedPublicKey]) {
            // 纯签名
            let sigValueHex2 = sm2.doSignature(msgString, privateKey, {
                pointPool: [sm2.getPoint(), sm2.getPoint(), sm2.getPoint(), sm2.getPoint()],
            })
            let verifyResult2 = sm2.doVerifySignature(msgString, sigValueHex2, publicKey)
            expect(verifyResult2).toBe(true)
        }
    })
    it('signature and generate ec point with asn.1 der encoding', ({ unCompressedPublicKey, compressedPublicKey, privateKey }) => {
        for (const publicKey of [unCompressedPublicKey, compressedPublicKey]) {

            // 纯签名 + 生成椭圆曲线点 + der编解码
            let sigValueHex3 = sm2.doSignature(msgString, privateKey, {
                der: true,
            })
            let verifyResult3 = sm2.doVerifySignature(msgString, sigValueHex3, publicKey, {
                der: true,
            })
            expect(verifyResult3).toBe(true)
        }
    })
    it('signature and generate ec point with sm3 hash for 10 times', ({ unCompressedPublicKey, compressedPublicKey, privateKey }) => {
        for (const publicKey of [unCompressedPublicKey, compressedPublicKey]) {
            // 纯签名 + 生成椭圆曲线点 + sm3杂凑
            let sigValueHex4 = sm2.doSignature(msgString, privateKey, {
                hash: true,
            })
            let verifyResult4 = sm2.doVerifySignature(msgString, sigValueHex4, publicKey, {
                hash: true,
            })
            expect(verifyResult4).toBe(true)

            for (let i = 0; i < 10; i++) {
                sigValueHex4 = sm2.doSignature(msgString, privateKey, {
                    hash: true,
                })
                verifyResult4 = sm2.doVerifySignature(msgString, sigValueHex4, publicKey, {
                    hash: true,
                })
                expect(verifyResult4).toBe(true)
            }

        }
    })
    it('signature and generate ec point with sm3 hash without public key inferring', ({ unCompressedPublicKey, compressedPublicKey, privateKey }) => {
        for (const publicKey of [unCompressedPublicKey, compressedPublicKey]) {
            // 纯签名 + 生成椭圆曲线点 + sm3杂凑（不做公钥推导）
            let sigValueHex5 = sm2.doSignature(msgString, privateKey, {
                hash: true,
                publicKey,
            })
            let verifyResult5 = sm2.doVerifySignature(msgString, sigValueHex5, publicKey, {
                hash: true,
                // publicKey,
            })
            expect(verifyResult5).toBe(true)
        }
    })
    it('signature and generate ec point with sm3 hash and userId without public key inferring', ({ unCompressedPublicKey, compressedPublicKey, privateKey }) => {
        for (const publicKey of [unCompressedPublicKey, compressedPublicKey]) {
            // 纯签名 + 生成椭圆曲线点 + sm3杂凑 + 不做公钥推 + 添加 userId
            let sigValueHex6 = sm2.doSignature(msgString, privateKey, {
                hash: true,
                publicKey,
                userId: 'testUserId',
            })
            let verifyResult6 = sm2.doVerifySignature(msgString, sigValueHex6, publicKey, {
                hash: true,
                userId: 'testUserId',
            })
            expect(verifyResult6).toBe(true)
            verifyResult6 = sm2.doVerifySignature(msgString, sigValueHex6, publicKey, {
                hash: true,
                userId: 'wrongTestUserId',
            })
            expect(verifyResult6).toBe(false)
            sigValueHex6 = sm2.doSignature(msgString, privateKey, {
                hash: true,
                publicKey,
                userId: '',
            })
            verifyResult6 = sm2.doVerifySignature(msgString, sigValueHex6, publicKey, {
                hash: true,
                userId: '',
            })
            expect(verifyResult6).toBe(true)
            verifyResult6 = sm2.doVerifySignature(msgString, sigValueHex6, publicKey, {
                hash: true,
            })
            expect(verifyResult6).toBe(false)
            sigValueHex6 = sm2.doSignature(msgString, privateKey, {
                hash: true,
                publicKey,
            })
            verifyResult6 = sm2.doVerifySignature(msgString, sigValueHex6, publicKey, {
                hash: true,
            })
            expect(verifyResult6).toBe(true)
            verifyResult6 = sm2.doVerifySignature(msgString, sigValueHex6, publicKey, {
                hash: true,
                userId: '',
            })
            expect(verifyResult6).toBe(false)
            verifyResult6 = sm2.doVerifySignature(msgString, sigValueHex6, publicKey, {
                hash: true,
                userId: '1234567812345678'
            })
            expect(verifyResult6).toBe(true)
        }
    })
})

describe('sm2: precomputed public key', () => {
    it('precompute successfully', (ctx) => {
        let precomputedPublicKey = sm2.precomputePublicKey(ctx.unCompressedPublicKey)
        expect(precomputedPublicKey).toBeDefined()
    })
    it('use precomputed key to encrypt data', (ctx) => {
        const precomputedPublicKey = sm2.precomputePublicKey(ctx.unCompressedPublicKey)
        let encryptData = sm2.doEncrypt(msgString, precomputedPublicKey, cipherMode)
        let decryptData = sm2.doDecrypt(encryptData, ctx.privateKey, cipherMode)
        expect(decryptData).toBe(msgString)
    })
    it('use precomputed key to verify data', (ctx) => {
        const precomputedPublicKey = sm2.precomputePublicKey(ctx.unCompressedPublicKey)
        let sigValueHex = sm2.doSignature(msgString, ctx.privateKey)
        let verifyResult = sm2.doVerifySignature(msgString, sigValueHex, precomputedPublicKey)
        expect(verifyResult).toBe(true)
    })
})

describe('sm2: chinese encoding', () => {
    it('signature and verify correctly', (ctx) => {
        let str = 'SM国密2'
        let sigValueHex = sm2.doSignature(str, ctx.privateKey, {
            hash: true,
            der: true,
        })
        let verifyResult = sm2.doVerifySignature(str, sigValueHex, ctx.unCompressedPublicKey, {
            der: true,
            hash: true,
        })
        expect(verifyResult).toBe(true)
        console.log({
            str,
            pk: ctx.unCompressedPublicKey,
            sigValueHex,
            verifyResult,
        })
    })
})