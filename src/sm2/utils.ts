/* eslint-disable no-bitwise, no-mixed-operators, no-use-before-define, max-len */
import * as utils from '@noble/curves/abstract/utils';

import { sm2Curve, sm2Fp } from './ec';
import { mod } from '@noble/curves/abstract/modular';
import { ONE, TWO, ZERO } from './bn';

export interface KeyPair {
  privateKey: string
  publicKey: string
}

/**
 * 生成密钥对：publicKey = privateKey * G
 */
export function generateKeyPairHex(str?: string): KeyPair {
  const privateKey = str ? utils.numberToBytesBE((mod(BigInt(str), ONE) + ONE), 32) : sm2Curve.utils.randomPrivateKey()
  // const random = typeof a === 'string' ? new BigInteger(a, b) :
  //   a ? new BigInteger(a, b!, c!) : new BigInteger(n.bitLength(), rng)
  // const d = random.mod(n.subtract(BigInteger.ONE)).add(BigInteger.ONE) // 随机数
  // const privateKey = leftPad(d.toString(16), 64)

  // const P = G!.multiply(d) // P = dG，p 为公钥，d 为私钥
  // const Px = leftPad(P.getX().toBigInteger().toString(16), 64)
  // const Py = leftPad(P.getY().toBigInteger().toString(16), 64)
  // const publicKey = '04' + Px + Py
  const publicKey = sm2Curve.getPublicKey(privateKey, false);
  const privPad = leftPad(utils.bytesToHex(privateKey), 64)
  const pubPad = leftPad(utils.bytesToHex(publicKey), 64)
  return {privateKey: privPad, publicKey: pubPad}
}

/**
 * 生成压缩公钥
 */
export function compressPublicKeyHex(s: string) {
  if (s.length !== 130) throw new Error('Invalid public key to compress')

  const len = (s.length - 2) / 2
  const xHex = s.substring(2, 2 + len)
  const y = utils.hexToNumber(s.substring(len + 2, len + len + 2))

  let prefix = '03'
  if (mod(y, TWO) === ZERO) prefix = '02'
  return prefix + xHex
}

/**
 * utf8串转16进制串
 */
export function utf8ToHex(input: string) {
  const bytes = utils.utf8ToBytes(input)
  return utils.bytesToHex(bytes)
}

/**
 * 补全16进制字符串
 */
export function leftPad(input: string, num: number) {
  if (input.length >= num) return input

  return (new Array(num - input.length + 1)).join('0') + input
}

/**
 * 转成16进制串
 */
export function arrayToHex(arr: number[]) {
  return arr.map(item => {
    const hex = item.toString(16)
    return hex.length === 1 ? '0' + hex : hex
  }).join('')
}

/**
 * 转成utf8串
 */
export function arrayToUtf8(arr: Uint8Array) {
  const str: string[] = []
  for (let i = 0, len = arr.length; i < len; i++) {
    if (arr[i] >= 0xf0 && arr[i] <= 0xf7) {
      // 四字节
      str.push(String.fromCodePoint(((arr[i] & 0x07) << 18) + ((arr[i + 1] & 0x3f) << 12) + ((arr[i + 2] & 0x3f) << 6) + (arr[i + 3] & 0x3f)))
      i += 3
    } else if (arr[i] >= 0xe0 && arr[i] <= 0xef) {
      // 三字节
      str.push(String.fromCodePoint(((arr[i] & 0x0f) << 12) + ((arr[i + 1] & 0x3f) << 6) + (arr[i + 2] & 0x3f)))
      i += 2
    } else if (arr[i] >= 0xc0 && arr[i] <= 0xdf) {
      // 双字节
      str.push(String.fromCodePoint(((arr[i] & 0x1f) << 6) + (arr[i + 1] & 0x3f)))
      i++
    } else {
      // 单字节
      str.push(String.fromCodePoint(arr[i]))
    }
  }

  return str.join('')
}

/**
 * 转成字节数组
 */
export function hexToArray(hexStr: string) {
  let hexStrLength = hexStr.length

  if (hexStrLength % 2 !== 0) {
    hexStr = leftPad(hexStr, hexStrLength + 1)
  }

  hexStrLength = hexStr.length
  const wordLength = hexStrLength / 2
  const words = new Uint8Array(wordLength)

  for (let i = 0; i < wordLength; i++) {
    words[i] = (parseInt(hexStr.substring(i * 2, i * 2 + 2), 16))
  }
  return words
}

/**
 * 验证公钥是否为椭圆曲线上的点
 */
export function verifyPublicKey(publicKey: string) {
  const point = sm2Curve.ProjectivePoint.fromHex(publicKey)
  if (!point) return false
  try {
    point.assertValidity()
    return true
  } catch (error) {
    return false
  }
}

/**
 * 验证公钥是否等价，等价返回true
 */
export function comparePublicKeyHex(publicKey1: string, publicKey2: string) {
  const point1 = sm2Curve.ProjectivePoint.fromHex(publicKey1)
  if (!point1) return false

  const point2 = sm2Curve.ProjectivePoint.fromHex(publicKey2)
  if (!point2) return false

  return point1.equals(point2)
}
