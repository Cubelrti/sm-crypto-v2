import { bytesToHex } from '@/sm3/utils'
import { rotl } from '../sm2/sm3'
import { arrayToHex, arrayToUtf8, hexToArray } from '../sm2/utils'
import { utf8ToArray } from '../sm3'

/* eslint-disable no-bitwise, no-mixed-operators, complexity */
const DECRYPT = 0
const ROUND = 32
const BLOCK = 16

const Sbox = Uint8Array.from([
  0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
  0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
  0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
  0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
  0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
  0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
  0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
  0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
  0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
  0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
  0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
  0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
  0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
  0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
  0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
  0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
])

const CK = new Uint32Array([
  0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
  0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
  0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
  0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
  0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
  0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
  0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
  0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
])

/**
 * 非线性变换
 */
function byteSub(a: number) {
  return (Sbox[a >>> 24 & 0xFF] & 0xFF) << 24 |
    (Sbox[a >>> 16 & 0xFF] & 0xFF) << 16 |
    (Sbox[a >>> 8 & 0xFF] & 0xFF) << 8 |
    (Sbox[a & 0xFF] & 0xFF)
}

/**
 * 线性变换，加密/解密用
 */
function l1(b: number) {
  return b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)
}

/**
 * 线性变换，生成轮密钥用
 */
function l2(b: number) {
  return b ^ rotl(b, 13) ^ rotl(b, 23)
}

/**
 * 以一组 128 比特进行加密/解密操作
 */
const x = new Uint32Array(4)
const tmp = new Uint32Array(4)
function sms4Crypt(input: Uint8Array, output: Uint8Array, roundKey: Uint32Array) {
  let x0 = 0, x1 = 0, x2 = 0, x3 = 0, tmp0 = 0, tmp1 = 0, tmp2 = 0, tmp3 = 0;

  // Unroll the first loop
  tmp0 = input[0] & 0xff;
  tmp1 = input[1] & 0xff;
  tmp2 = input[2] & 0xff;
  tmp3 = input[3] & 0xff;
  x0 = tmp0 << 24 | tmp1 << 16 | tmp2 << 8 | tmp3;

  tmp0 = input[4] & 0xff;
  tmp1 = input[5] & 0xff;
  tmp2 = input[6] & 0xff;
  tmp3 = input[7] & 0xff;
  x1 = tmp0 << 24 | tmp1 << 16 | tmp2 << 8 | tmp3;

  tmp0 = input[8] & 0xff;
  tmp1 = input[9] & 0xff;
  tmp2 = input[10] & 0xff;
  tmp3 = input[11] & 0xff;
  x2 = tmp0 << 24 | tmp1 << 16 | tmp2 << 8 | tmp3;

  tmp0 = input[12] & 0xff;
  tmp1 = input[13] & 0xff;
  tmp2 = input[14] & 0xff;
  tmp3 = input[15] & 0xff;
  x3 = tmp0 << 24 | tmp1 << 16 | tmp2 << 8 | tmp3;

  for (let r = 0; r < 32; r += 4) {
    // Inlined l1 and rotl functions and avoid the mid variable
    tmp0 = x1 ^ x2 ^ x3 ^ roundKey[r];
    tmp0 = byteSub(tmp0);  // byteSub is another function we should inline if possible.
    x0 ^= tmp0 ^ ((tmp0 << 2) | (tmp0 >>> 30)) ^ ((tmp0 << 10) | (tmp0 >>> 22)) ^ ((tmp0 << 18) | (tmp0 >>> 14)) ^ ((tmp0 << 24) | (tmp0 >>> 8));

    tmp1 = x2 ^ x3 ^ x0 ^ roundKey[r + 1];
    tmp1 = byteSub(tmp1);
    x1 ^= tmp1 ^ ((tmp1 << 2) | (tmp1 >>> 30)) ^ ((tmp1 << 10) | (tmp1 >>> 22)) ^ ((tmp1 << 18) | (tmp1 >>> 14)) ^ ((tmp1 << 24) | (tmp1 >>> 8));

    tmp2 = x3 ^ x0 ^ x1 ^ roundKey[r + 2];
    tmp2 = byteSub(tmp2);
    x2 ^= tmp2 ^ ((tmp2 << 2) | (tmp2 >>> 30)) ^ ((tmp2 << 10) | (tmp2 >>> 22)) ^ ((tmp2 << 18) | (tmp2 >>> 14)) ^ ((tmp2 << 24) | (tmp2 >>> 8));

    tmp3 = x0 ^ x1 ^ x2 ^ roundKey[r + 3];
    tmp3 = byteSub(tmp3);
    x3 ^= tmp3 ^ ((tmp3 << 2) | (tmp3 >>> 30)) ^ ((tmp3 << 10) | (tmp3 >>> 22)) ^ ((tmp3 << 18) | (tmp3 >>> 14)) ^ ((tmp3 << 24) | (tmp3 >>> 8));
  }

  // Unroll the last loop
  output[0] = x3 >>> 24 & 0xff;
  output[1] = x3 >>> 16 & 0xff;
  output[2] = x3 >>> 8 & 0xff;
  output[3] = x3 & 0xff;

  output[4] = x2 >>> 24 & 0xff;
  output[5] = x2 >>> 16 & 0xff;
  output[6] = x2 >>> 8 & 0xff;
  output[7] = x2 & 0xff;

  output[8] = x1 >>> 24 & 0xff;
  output[9] = x1 >>> 16 & 0xff;
  output[10] = x1 >>> 8 & 0xff;
  output[11] = x1 & 0xff;

  output[12] = x0 >>> 24 & 0xff;
  output[13] = x0 >>> 16 & 0xff;
  output[14] = x0 >>> 8 & 0xff;
  output[15] = x0 & 0xff;
}

/**
 * 密钥扩展算法
 */
function sms4KeyExt(key: Uint8Array, roundKey: Uint32Array, cryptFlag: 0 | 1) {
  let x0 = 0, x1 = 0, x2 = 0, x3 = 0, mid = 0;

  // Unwrap the first loop and use local variables instead of the array x
  x0 = (key[0] & 0xff) << 24 | (key[1] & 0xff) << 16 | (key[2] & 0xff) << 8 | (key[3] & 0xff);
  x1 = (key[4] & 0xff) << 24 | (key[5] & 0xff) << 16 | (key[6] & 0xff) << 8 | (key[7] & 0xff);
  x2 = (key[8] & 0xff) << 24 | (key[9] & 0xff) << 16 | (key[10] & 0xff) << 8 | (key[11] & 0xff);
  x3 = (key[12] & 0xff) << 24 | (key[13] & 0xff) << 16 | (key[14] & 0xff) << 8 | (key[15] & 0xff);

  // 与系统参数做异或
  x0 ^= 0xa3b1bac6;
  x1 ^= 0x56aa3350;
  x2 ^= 0x677d9197;
  x3 ^= 0xb27022dc;

  for (let r = 0; r < 32; r += 4) {
    mid = x1 ^ x2 ^ x3 ^ CK[r + 0];
    mid = byteSub(mid);  // Again, if possible, inline the byteSub function.
    x0 ^= mid ^ ((mid << 13) | (mid >>> 19)) ^ ((mid << 23) | (mid >>> 9));
    roundKey[r + 0] = x0;

    mid = x2 ^ x3 ^ x0 ^ CK[r + 1];
    mid = byteSub(mid);
    x1 ^= mid ^ ((mid << 13) | (mid >>> 19)) ^ ((mid << 23) | (mid >>> 9));
    roundKey[r + 1] = x1;

    mid = x3 ^ x0 ^ x1 ^ CK[r + 2];
    mid = byteSub(mid);
    x2 ^= mid ^ ((mid << 13) | (mid >>> 19)) ^ ((mid << 23) | (mid >>> 9));
    roundKey[r + 2] = x2;

    mid = x0 ^ x1 ^ x2 ^ CK[r + 3];
    mid = byteSub(mid);
    x3 ^= mid ^ ((mid << 13) | (mid >>> 19)) ^ ((mid << 23) | (mid >>> 9));
    roundKey[r + 3] = x3;
  }

  if (cryptFlag === DECRYPT) {
    for (let r = 0; r < 16; r++) {
      // Use destructuring to swap elements
      [roundKey[r], roundKey[31 - r]] = [roundKey[31 - r], roundKey[r]];
    }
  }
}

export interface SM4Options {
  padding?: 'pkcs#7' | 'pkcs#5' | 'none' | null
  mode?: 'cbc' | 'ecb'
  iv?: Uint8Array | string
  output?: 'string' | 'array'
}

const blockOutput = new Uint8Array(16)
export function sm4(inArray: Uint8Array | string, key: Uint8Array | string, cryptFlag: 0 | 1, options: SM4Options = {}) {
  let {
    padding = 'pkcs#7',
    mode,
    iv = new Uint8Array(16),
    output
  } = options
  if (mode === 'cbc') {
    // CBC 模式，默认走 ECB 模式
    if (typeof iv === 'string') iv = hexToArray(iv)
    if (iv.length !== (128 / 8)) {
      // iv 不是 128 比特
      throw new Error('iv is invalid')
    }
  }

  // 检查 key
  if (typeof key === 'string') key = hexToArray(key)
  if (key.length !== (128 / 8)) {
    // key 不是 128 比特
    throw new Error('key is invalid')
  }

  // 检查输入
  if (typeof inArray === 'string') {
    if (cryptFlag !== DECRYPT) {
      // 加密，输入为 utf8 串
      inArray = utf8ToArray(inArray)
    } else {
      // 解密，输入为 16 进制串
      inArray = hexToArray(inArray)
    }
  } else {
    inArray = Uint8Array.from(inArray)
  }

  // 新增填充，sm4 是 16 个字节一个分组，所以统一走到 pkcs#7
  if ((padding === 'pkcs#5' || padding === 'pkcs#7') && cryptFlag !== DECRYPT) {
    const paddingCount = BLOCK - inArray.length % BLOCK
    const newArray = new Uint8Array(inArray.length + paddingCount)
    newArray.set(inArray, 0)
    for (let i = 0; i < paddingCount; i++) newArray[inArray.length + i] = paddingCount
    inArray = newArray
  }

  // 生成轮密钥
  const roundKey = new Uint32Array(ROUND)
  sms4KeyExt(key, roundKey, cryptFlag)

  let outArray = new Uint8Array(inArray.length)
  let lastVector = iv as Uint8Array
  let restLen = inArray.length
  let point = 0
  while (restLen >= BLOCK) {
    const input = inArray.subarray(point, point + 16)

    if (mode === 'cbc') {
      for (let i = 0; i < BLOCK; i++) {
        if (cryptFlag !== DECRYPT) {
          // 加密过程在组加密前进行异或
          input[i] ^= lastVector[i]
        }
      }
    }

    sms4Crypt(input, blockOutput, roundKey)


    for (let i = 0; i < BLOCK; i++) {
      if (mode === 'cbc') {
        if (cryptFlag === DECRYPT) {
          // 解密过程在组解密后进行异或
          blockOutput[i] ^= lastVector[i]
        }
      }

      outArray[point + i] = blockOutput[i]
    }

    if (mode === 'cbc') {
      if (cryptFlag !== DECRYPT) {
        // 使用上一次输出作为加密向量
        lastVector = blockOutput
      } else {
        // 使用上一次输入作为解密向量
        lastVector = input
      }
    }

    restLen -= BLOCK
    point += BLOCK
  }

  // 去除填充，sm4 是 16 个字节一个分组，所以统一走到 pkcs#7
  if ((padding === 'pkcs#5' || padding === 'pkcs#7') && cryptFlag === DECRYPT) {
    const len = outArray.length
    const paddingCount = outArray[len - 1]
    for (let i = 1; i <= paddingCount; i++) {
      if (outArray[len - i] !== paddingCount) throw new Error('padding is invalid')
    }
    outArray = outArray.slice(0, len - paddingCount)
  }

  // 调整输出
  if (output !== 'array') {
    if (cryptFlag !== DECRYPT) {
      // 加密，输出转 16 进制串
      return bytesToHex(outArray)
    } else {
      // 解密，输出转 utf8 串
      return arrayToUtf8(outArray)
    }
  } else {
    return outArray
  }
}

export function encrypt(
  inArray: Uint8Array | string,
  key: Uint8Array | string,
  options?: { output: 'array' } & SM4Options
): Uint8Array
export function encrypt(
  inArray: Uint8Array | string,
  key: Uint8Array | string,
  options?: { output: 'string' } & SM4Options
): string
export function encrypt(
  inArray: Uint8Array | string,
  key: Uint8Array | string,
  options: SM4Options = {}
) {
  return sm4(inArray, key, 1, options)
}

export function decrypt(
  inArray: Uint8Array | string,
  key: Uint8Array | string,
  options?: { output: 'array' } & SM4Options
): Uint8Array
export function decrypt(
  inArray: Uint8Array | string,
  key: Uint8Array | string,
  options?: { output: 'string' } & SM4Options
): string
export function decrypt(inArray: Uint8Array | string, key: Uint8Array | string, options: SM4Options = {}) {
  return sm4(inArray, key, 0, options)
}