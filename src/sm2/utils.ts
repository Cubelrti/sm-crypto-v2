/* eslint-disable no-bitwise, no-mixed-operators, no-use-before-define, max-len */
import { BigInteger, RandomGenerator, SecureRandom } from 'jsbn'
import { ECCurveFp } from './ec'
import { weierstrass } from '@noble/curves/abstract/weierstrass';
import { Field } from '@noble/curves/abstract/modular'; // finite field for mod arithmetics
import { hmac, sm3 } from './sm3'
import * as utils from '@noble/curves/abstract/utils';

import { utf8ToArray } from '@/sm3'

declare module 'jsbn' {
  export class SecureRandom implements RandomGenerator {
    nextBytes(bytes: number[]): void;
  }
}

const rng = new SecureRandom()
const {curve, G, n} = generateEcparam()

/**
 * 获取公共椭圆曲线
 */
export function getGlobalCurve() {
  return curve
}

/**
 * 生成ecparam
 */
export function generateEcparam() {
  // 椭圆曲线
  const p = new BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16)
  const a = new BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16)
  const b = new BigInteger('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', 16)
  const curve = new ECCurveFp(p, a, b)

  // 基点
  const gxHex = '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7'
  const gyHex = 'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0'
  const G = curve.decodePointHex('04' + gxHex + gyHex)!

  const n = new BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16)

  return {curve, G, n}
}

// import { sha256 } from '@noble/hashes/sha256'; // 3rd-party sha256() of type utils.CHash
// import { hmac } from '@noble/hashes/hmac'; // 3rd-party hmac() that will accept sha256()
// import { concatBytes, randomBytes } from '@noble/hashes/utils'; // 3rd-party utilities
export function createHash() {
  const hashC = (msg: Uint8Array | string): Uint8Array => sm3(typeof msg === 'string' ? utf8ToArray(msg) : msg)
  hashC.outputLen = 256;
  hashC.blockLen = 512;
  hashC.create = () => sm3(Uint8Array.from([]));
  return hashC;
}
export const sm2Curve = weierstrass({
  // sm2: short weierstrass.
  a: 115792089210356248756420345214020892766250353991924191454421193933289684991996n,
  b: 18505919022281880113072981827955639221458448578012075254857346196103069175443n,
  Fp: Field(115792089210356248756420345214020892766250353991924191454421193933289684991999n),
  h: 1n,
  n: 115792089210356248756420345214020892766061623724957744567843809356293439045923n,
  Gx: 22963146547237050559479531362550074578802567295341616970375194840604139615431n,
  Gy: 85132369209828568825618990617112496413088388631904505083283536607588877201568n,
  hash: createHash(),
  hmac: (key: Uint8Array, ...msgs: Uint8Array[]) => hmac(concatArray(...msgs), key),
  randomBytes: (n) => {
    return new Uint8Array(n ?? 0).map(() => Math.floor(Math.random() * 256));
  },
});

/**
 * 生成密钥对：publicKey = privateKey * G
 */
export function generateKeyPairHex(a?: number | string, b?: number, c?: RandomGenerator) {
  // const random = typeof a === 'string' ? new BigInteger(a, b) :
  //   a ? new BigInteger(a, b!, c!) : new BigInteger(n.bitLength(), rng)
  // const d = random.mod(n.subtract(BigInteger.ONE)).add(BigInteger.ONE) // 随机数
  // const privateKey = leftPad(d.toString(16), 64)

  // const P = G!.multiply(d) // P = dG，p 为公钥，d 为私钥
  // const Px = leftPad(P.getX().toBigInteger().toString(16), 64)
  // const Py = leftPad(P.getY().toBigInteger().toString(16), 64)
  // const publicKey = '04' + Px + Py
  const privateKey = sm2Curve.utils.randomPrivateKey();
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
  const y = new BigInteger(s.substring(len + 2, len + len + 2), 16)

  let prefix = '03'
  if (y.mod(new BigInteger('2')).equals(BigInteger.ZERO)) prefix = '02'
  return prefix + xHex
}

/**
 * utf8串转16进制串
 */
export function utf8ToHex(input: string) {
  input = decodeURIComponent(encodeURIComponent(input))

  const length = input.length

  // 转换到字数组
  const words = new Uint32Array((length >>> 2) + 1)
  for (let i = 0; i < length; i++) {
    words[i >>> 2] |= (input.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8)
  }

  // 转换到16进制
  const hexChars: string[]= []
  for (let i = 0; i < length; i++) {
    const bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff
    hexChars.push((bite >>> 4).toString(16))
    hexChars.push((bite & 0x0f).toString(16))
  }

  return hexChars.join('')
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
  const point = curve.decodePointHex(publicKey)
  if (!point) return false

  const x = point.getX()
  const y = point.getY()

  // 验证 y^2 是否等于 x^3 + ax + b
  return y.square().equals(x.multiply(x.square()).add(x.multiply(curve.a)).add(curve.b))
}

/**
 * 验证公钥是否等价，等价返回true
 */
export function comparePublicKeyHex(publicKey1: string, publicKey2: string) {
  const point1 = curve.decodePointHex(publicKey1)
  if (!point1) return false

  const point2 = curve.decodePointHex(publicKey2)
  if (!point2) return false

  return point1.equals(point2)
}


export function concatArray(...arrays: Uint8Array[]) {
  // sum of individual array lengths
  let totalLength = arrays.reduce((acc, value) => acc + value.length, 0);

  if (!arrays.length) return new Uint8Array();

  let result = new Uint8Array(totalLength);

  // for each array - copy it over result
  // next array is copied right after the previous one
  let length = 0;
  for (let array of arrays) {
    result.set(array, length);
    length += array.length;
  }

  return result;
}
