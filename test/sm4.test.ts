import { sm4 } from '@/index'
import { hexToArray } from '@/sm2'
import { bytesToHex } from '@/sm3/utils'
import { test, expect } from 'vitest'

const msg = 'hello world! 我是 juneandgreen.'
const input = Uint8Array.from([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10])
const output_1 = Uint8Array.from([0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46, 0x00, 0x2a, 0x8a, 0x4e, 0xfa, 0x86, 0x3c, 0xca, 0xd0, 0x24, 0xac, 0x03, 0x00, 0xbb, 0x40, 0xd2])
const output_2 = Uint8Array.from([0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46])
const output_3 = Uint8Array.from([0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46, 0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46, 0x00, 0x2a, 0x8a, 0x4e, 0xfa, 0x86, 0x3c, 0xca, 0xd0, 0x24, 0xac, 0x03, 0x00, 0xbb, 0x40, 0xd2])
const outputHexStr_1 = '681edf34d206965e86b3e94f536e4246002a8a4efa863ccad024ac0300bb40d2'
const outputHexStr_2 = '681edf34d206965e86b3e94f536e4246'
const outputHexStr_3 = '681edf34d206965e86b3e94f536e4246681edf34d206965e86b3e94f536e4246002a8a4efa863ccad024ac0300bb40d2'
const input2 = Uint8Array.from([0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x20, 0xe6, 0x88, 0x91, 0xe6, 0x98, 0xaf, 0x20, 0x6a, 0x75, 0x6e, 0x65, 0x61, 0x6e, 0x64, 0x67, 0x72, 0x65, 0x65, 0x6e, 0x2e])
const output2HexStr = '0e395deb10f6e8a17e17823e1fd9bd98a1bff1df508b5b8a1efb79ec633d1bb129432ac1b74972dbe97bab04f024e89c'
const output3HexStr = '0d6cfa73c823b2ac0d6a92c564171892000fbea90be7a4d440bc58a9044fcb5f3d1615d91a6dbfb4dfb0c6915071527b'
const output2 = Uint8Array.from([0x0e, 0x39, 0x5d, 0xeb, 0x10, 0xf6, 0xe8, 0xa1, 0x7e, 0x17, 0x82, 0x3e, 0x1f, 0xd9, 0xbd, 0x98, 0xa1, 0xbf, 0xf1, 0xdf, 0x50, 0x8b, 0x5b, 0x8a, 0x1e, 0xfb, 0x79, 0xec, 0x63, 0x3d, 0x1b, 0xb1, 0x29, 0x43, 0x2a, 0xc1, 0xb7, 0x49, 0x72, 0xdb, 0xe9, 0x7b, 0xab, 0x04, 0xf0, 0x24, 0xe8, 0x9c])
const iv = Uint8Array.from([0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef])
const ivHexStr = 'fedcba98765432100123456789abcdef'
const key = Uint8Array.from([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10])
const keyHexStr = '0123456789abcdeffedcba9876543210'

test('sm4: encrypt a group', () => {
    expect(sm4.encrypt(input, key)).toBe(outputHexStr_1)
    expect(sm4.encrypt(input, key, {output: 'array'})).toEqual(output_1)
    expect(sm4.encrypt(input, key, {padding: 'pkcs#5'})).toBe(outputHexStr_1)
    expect(sm4.encrypt(input, key, {padding: 'pkcs#5', output: 'array'})).toEqual(output_1)
    expect(sm4.encrypt(input, key, {padding: 'none'})).toBe(outputHexStr_2)
    expect(sm4.encrypt(input, key, {padding: 'none', output: 'array'})).toEqual(output_2)
    expect(sm4.encrypt(msg, keyHexStr)).toBe(output2HexStr)
    expect(sm4.encrypt(msg, keyHexStr, {output: 'array'})).toEqual(output2)
    expect(sm4.encrypt(msg, keyHexStr, {mode: 'cbc', iv})).toBe(output3HexStr)
    expect(sm4.encrypt(msg, keyHexStr, {mode: 'cbc', iv: ivHexStr})).toBe(output3HexStr)
    expect(sm4.encrypt(input2, keyHexStr)).toBe(output2HexStr)
    expect(sm4.encrypt(input2, keyHexStr, {output: 'array'})).toEqual(output2)
})

test('sm4: decrypt a group', () => {
    expect(sm4.decrypt(outputHexStr_1, key, {output: 'array'})).toEqual(input)
    expect(sm4.decrypt(output_1, key, {output: 'array'})).toEqual(input)
    expect(sm4.decrypt(outputHexStr_2, key, {padding: 'none', output: 'array'})).toEqual(input)
    expect(sm4.decrypt(output_2, key, {padding: 'none', output: 'array'})).toEqual(input)
    expect(sm4.decrypt(output2HexStr, keyHexStr)).toBe(msg)
    expect(sm4.decrypt(output2, keyHexStr)).toBe(msg)
    expect(sm4.decrypt(output2HexStr, keyHexStr, {output: 'array'})).toEqual(input2)
    expect(sm4.decrypt(output3HexStr, keyHexStr, {mode: 'cbc', iv})).toBe(msg)
    expect(sm4.decrypt(output3HexStr, keyHexStr, {mode: 'cbc', iv: ivHexStr})).toBe(msg)
    expect(sm4.decrypt(output2, keyHexStr, {output: 'array'})).toEqual(input2)
})

test('sm4: encrypt several groups', () => {
    expect(sm4.encrypt(Uint8Array.from([...input, ...input]), key)).toBe(outputHexStr_3)
    expect(sm4.encrypt(Uint8Array.from([...input, ...input]), key, {output: 'array'})).toEqual(output_3)
    expect(sm4.encrypt(Uint8Array.from([...input, ...input]), key, {padding: 'none'})).toBe(outputHexStr_2 + outputHexStr_2)
    expect(sm4.encrypt(Uint8Array.from([...input, ...input]), key, {padding: 'none', output: 'array'})).toEqual(Uint8Array.from([...output_2, ...output_2]))
})

test('sm4: decrypt several groups', () => {
    expect(sm4.decrypt(outputHexStr_3, key, {output: 'array'})).toEqual(Uint8Array.from([...input, ...input]))
    expect(sm4.decrypt(output_3, key, {output: 'array'})).toEqual(Uint8Array.from([...input, ...input]))
    expect(sm4.decrypt(outputHexStr_2 + outputHexStr_2, key, {padding: 'none', output: 'array'})).toEqual(Uint8Array.from([...input, ...input]))
    expect(sm4.decrypt(Uint8Array.from([...output_2, ...output_2]), key, {padding: 'none', output: 'array'})).toEqual(Uint8Array.from([...input, ...input]))
})

test('sm4: encrypt unicode string', () => {
    expect(sm4.encrypt('🇨🇳𠮷😀😃😄😁😆😅', keyHexStr)).toBe('a0b1aac2e6db928ddfc8a081a6661d0452b44e5720db106714ffc8cbee29bcf7d96b4d64bffd07553e6a2ee096523b7f')
    expect(sm4.decrypt('a0b1aac2e6db928ddfc8a081a6661d0452b44e5720db106714ffc8cbee29bcf7d96b4d64bffd07553e6a2ee096523b7f', keyHexStr)).toBe('🇨🇳𠮷😀😃😄😁😆😅')
})

test('sm4: encrypt a group with 1000000 times', () => {
    let temp = input
    for (let i = 0; i < 1000000; i++) {
        temp = sm4.encrypt(temp, key, {padding: 'none', output: 'array'}) as Uint8Array
    }
    expect(temp).toEqual(Uint8Array.from([0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f, 0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66]))
})

test('sm4: invalid padding', () => {
    expect(() => sm4.decrypt('a0b1aac2e6db928ddfc8a081a6661d0452b44e5720db106714ffc8cbee29bcf7d96b4d64bffd07553e6a2ee096523b7a', keyHexStr)).toThrow('padding is invalid')
    expect(() => sm4.decrypt('a0b1aac2e6db928ddfc8a081a6661d0452b44e5720db106714ffc8cbee29bcf7d96b4d64bffd07553e6a2ee096523b7f', ivHexStr)).toThrow('padding is invalid')
})

test('sm4: gcm', () => {
    // Initialization Vector:   00001234567800000000ABCD
    // Key:                     0123456789ABCDEFFEDCBA9876543210
    // Plaintext:               AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB
    //                          CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD
    //                          EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF
    //                          EEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA
    // Associated Data:         FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2
    // CipherText:              17F399F08C67D5EE19D0DC9969C4BB7D
    //                          5FD46FD3756489069157B282BB200735
    //                          D82710CA5C22F0CCFA7CBF93D496AC15
    //                          A56834CBCF98C397B4024A2691233B8D
    // Authentication Tag:      83DE3541E4C2B58177E065A9BF7B62EC

    const iv = '00001234567800000000abcd'
    const key = '0123456789abcdeffedcba9876543210'
    const plaintext = 'aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccddddddddddddddddeeeeeeeeeeeeeeeeffffffffffffffffeeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa'
    const plaintextArray = hexToArray(plaintext)
    const associatedData = 'feedfacedeadbeeffeedfacedeadbeefabaddad2'
    const expectedCiphertext = '17f399f08c67d5ee19d0dc9969c4bb7d5fd46fd3756489069157b282bb200735d82710ca5c22f0ccfa7cbf93d496ac15a56834cbcf98c397b4024a2691233b8d'
    const expectedAuthTag = '83de3541e4c2b58177e065a9bf7b62ec'
    
    // Test encryption
    const encryptResult = sm4.encrypt(plaintextArray, key, {
        mode: 'gcm',
        iv,
        associatedData,
        output: 'string',
    })
    
    // Check format with auth tag
    expect(encryptResult.output + encryptResult.tag).toBe(expectedCiphertext + expectedAuthTag)


    // return
    // Test encryption with array output
    const encryptArrayResult = sm4.encrypt(plaintextArray, key, {
        mode: 'gcm',
        iv,
        associatedData,
        output: 'array',
        outputTag: true
    })
    expect(encryptArrayResult.output).toEqual(Uint8Array.from(Buffer.from(expectedCiphertext, 'hex')))
    expect(encryptArrayResult.tag).toEqual(Uint8Array.from(Buffer.from(expectedAuthTag, 'hex')))
    
    // Test decryption
    const decryptedText = sm4.decrypt(expectedCiphertext, key, {
        mode: 'gcm',
        iv,
        associatedData,
        tag: expectedAuthTag,
        output: 'array'
    })
    expect(bytesToHex(decryptedText)).toBe(plaintext)
    
    // Test decryption with array input
    const decryptedArray = sm4.decrypt(
        Uint8Array.from(Buffer.from(expectedCiphertext, 'hex')),
        key,
        {
            mode: 'gcm',
            iv,
            associatedData,
            tag: Uint8Array.from(Buffer.from(expectedAuthTag, 'hex')),
            output: 'array'
        }
    )
    expect(decryptedArray).toEqual(plaintextArray)
    
    // Test tag verification failure
    const invalidTag = '83de3541e4c2b58177e065a9bf7b62ed'
    expect(() => {
        sm4.decrypt(expectedCiphertext, key, {
            mode: 'gcm',
            iv,
            associatedData,
            tag: invalidTag,
            output: 'string'
        })
    }).toThrow('authentication tag mismatch')
})