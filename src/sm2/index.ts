/* eslint-disable no-use-before-define */
import { encodeDer, decodeDer, encodeEnc, decodeEnc } from './asn1'
import { arrayToHex, arrayToUtf8, generateKeyPairHex, hexToArray, leftPad, utf8ToHex } from './utils'
import { sm3 } from './sm3'
import * as utils from '@noble/curves/abstract/utils';
import { field, sm2Curve } from './ec';
import { ONE, ZERO } from './bn';
import { bytesToHex } from '@/sm3/utils';
import { ProjPointType } from '@noble/curves/abstract/weierstrass';

export * from './utils'
export { initRNGPool } from './rng'
export { calculateSharedKey } from './kx'

const C1C2C3 = 0
// a empty array, just make tsc happy
export const EmptyArray = new Uint8Array()
/**
 * 加密
 */
export function doEncrypt(msg: string | Uint8Array, publicKey: string | ProjPointType<bigint>, cipherMode = 1, options?: {
  asn1?: boolean // 使用 ASN.1 对 C1 编码
}) {

  const msgArr = typeof msg === 'string' ? hexToArray(utf8ToHex(msg)) : Uint8Array.from(msg)
  const publicKeyPoint = typeof publicKey === 'string' ? sm2Curve.ProjectivePoint.fromHex(publicKey) :
    publicKey

  const keypair = generateKeyPairHex()
  const k = utils.hexToNumber(keypair.privateKey)

  // c1 = k * G
  let c1 = keypair.publicKey

  if (c1.length > 128) c1 = c1.substring(c1.length - 128)
  const p = publicKeyPoint.multiply(k)
  
  // (x2, y2) = k * publicKey
  const x2 = hexToArray(leftPad(utils.numberToHexUnpadded(p.x), 64))
  const y2 = hexToArray(leftPad(utils.numberToHexUnpadded(p.y), 64))

  // c3 = hash(x2 || msg || y2)
  const c3 = bytesToHex(sm3(utils.concatBytes(x2, msgArr, y2)));

  xorCipherStream(x2, y2, msgArr)
  const c2 = bytesToHex(msgArr)
  if (options?.asn1) {
    const point = sm2Curve.ProjectivePoint.fromHex(keypair.publicKey)
    const encode = cipherMode === C1C2C3 ? 
     encodeEnc(point.x, point.y, c2, c3) :
     encodeEnc(point.x, point.y, c3, c2)
    return encode
  }
  return cipherMode === C1C2C3 ? c1 + c2 + c3 : c1 + c3 + c2
}

function xorCipherStream(x2: Uint8Array, y2: Uint8Array, msg: Uint8Array) {
  let ct = 1
  let offset = 0
  let t = EmptyArray
  const ctShift = new Uint8Array(4)
  const nextT = () => {
    // (1) Hai = hash(z || ct)
    // (2) ct++
    ctShift[0] = ct >> 24 & 0x00ff
    ctShift[1] = ct >> 16 & 0x00ff
    ctShift[2] = ct >> 8 & 0x00ff
    ctShift[3] = ct & 0x00ff
    t = sm3(utils.concatBytes(x2, y2, ctShift))
    ct++
    offset = 0
  }
  nextT() // 先生成 Ha1

  for (let i = 0, len = msg.length; i < len; i++) {
    // t = Ha1 || Ha2 || Ha3 || Ha4
    if (offset === t.length) nextT()

    // c2 = msg ^ t
    msg[i] ^= t[offset++] & 0xff
  }

}

/**
 * 解密
 */
export function doDecrypt(encryptData: string, privateKey: string, cipherMode?: number, options?: {
  output: 'array'
  asn1?: boolean
}): Uint8Array
export function doDecrypt(encryptData: string, privateKey: string, cipherMode?: number, options?: {
  output: 'string',
  asn1?: boolean
}): string
export function doDecrypt(encryptData: string, privateKey: string, cipherMode = 1, {
  output = 'string',
  asn1 = false,
} = {}) {
  const privateKeyInteger = utils.hexToNumber(privateKey)

  let c1: ProjPointType<bigint>
  let c2: string
  let c3: string
  

  if (asn1) {
    const {x, y, cipher, hash} = decodeEnc(encryptData)
    c1 = sm2Curve.ProjectivePoint.fromAffine({ x, y })
    c3 = hash
    c2 = cipher
    if (cipherMode === C1C2C3) {
      [c2, c3] = [c3, c2]
    }
  } else {
    // c1c3c2
    c1 = sm2Curve.ProjectivePoint.fromHex('04' + encryptData.substring(0, 128))!
    c3 = encryptData.substring(128, 128 + 64)
    c2 = encryptData.substring(128 + 64)
  
    if (cipherMode === C1C2C3) {
      c3 = encryptData.substring(encryptData.length - 64)
      c2 = encryptData.substring(128, encryptData.length - 64)
    }
  }
  

  const msg = hexToArray(c2)
  const p = c1.multiply(privateKeyInteger)
  const x2 = hexToArray(leftPad(utils.numberToHexUnpadded(p.x), 64))
  const y2 = hexToArray(leftPad(utils.numberToHexUnpadded(p.y), 64))

  xorCipherStream(x2, y2, msg)
  // c3 = hash(x2 || msg || y2)
  const checkC3 = arrayToHex(Array.from(sm3(utils.concatBytes(x2, msg, y2))))
  
  if (checkC3 === c3.toLowerCase()) {
    return output === 'array' ? msg : arrayToUtf8(msg)
  } else {
    return output === 'array' ? [] : ''
  }
}

export interface SignaturePoint {
  k: bigint
  x1: bigint
}

/**
 * 签名
 */
export function doSignature(msg: Uint8Array | string, privateKey: string, options: {
  pointPool?: SignaturePoint[], der?: boolean, hash?: boolean, publicKey?: string, userId?: string
} = {}) {
  let {
    pointPool, der, hash, publicKey, userId
  } = options
  let hashHex = typeof msg === 'string' ? utf8ToHex(msg) : arrayToHex(Array.from(msg))
  if (hash) {
    // sm3杂凑
    publicKey = publicKey || getPublicKeyFromPrivateKey(privateKey)
    hashHex = getHash(hashHex, publicKey, userId)
  }

  const dA = utils.hexToNumber(privateKey)
  const e = utils.hexToNumber(hashHex)

  // k
  let k: bigint | null = null
  let r: bigint | null = null
  let s: bigint | null = null

  do {
    do {
      let point: SignaturePoint
      if (pointPool && pointPool.length) {
        point = pointPool.pop()!
      } else {
        point = getPoint()
      }
      k = point.k

      // r = (e + x1) mod n
      r = field.add(e, point.x1)
    } while (r === ZERO || (r + k) === sm2Curve.CURVE.n)

    // s = ((1 + dA)^-1 * (k - r * dA)) mod n
    s = field.mul(field.inv(field.addN(dA, ONE)), field.subN(k, field.mulN(r, dA)))
  } while (s === ZERO)
  if (der) return encodeDer(r, s) // asn.1 der 编码
  return leftPad(utils.numberToHexUnpadded(r), 64) + leftPad(utils.numberToHexUnpadded(s), 64)
}

/**
 * 验签
 */
export function doVerifySignature(msg: string | Uint8Array, signHex: string, publicKey: string | ProjPointType<bigint>, options: { der?: boolean, hash?: boolean, userId?: string } = {}) {
  let hashHex: string
  const {
    hash,
    der,
    userId,
  } = options
  const publicKeyHex = typeof publicKey === 'string' ? publicKey : publicKey.toHex(false)
  if (hash) {
    // sm3杂凑
    hashHex = getHash(typeof msg === 'string' ? utf8ToHex(msg) : msg, publicKeyHex, userId)
  } else {
    hashHex = typeof msg === 'string' ? utf8ToHex(msg) : arrayToHex(Array.from(msg))
  }

  let r: bigint;
  let s: bigint;
  if (der) {
    const decodeDerObj = decodeDer(signHex) // asn.1 der 解码
    r = decodeDerObj.r
    s = decodeDerObj.s
  } else {
    r = utils.hexToNumber(signHex.substring(0, 64))
    s = utils.hexToNumber(signHex.substring(64))
  }
  
  const PA = typeof publicKey === 'string' ? sm2Curve.ProjectivePoint.fromHex(publicKey) : publicKey
  const e = utils.hexToNumber(hashHex)
  
  // t = (r + s) mod n
  const t = field.add(r, s)

  if (t === ZERO) return false

  // x1y1 = s * G + t * PA
  const x1y1 = sm2Curve.ProjectivePoint.BASE.multiply(s).add(PA.multiply(t))

  // R = (e + x1) mod n
  // const R = e.add(x1y1.getX().toBigInteger()).mod(n)
  const R = field.add(e, x1y1.x)

  // return r.equals(R)
  return r === R
}

export function getZ(publicKey: string, userId = '1234567812345678') {
  // z = hash(entl || userId || a || b || gx || gy || px || py)
  userId = utf8ToHex(userId)
  const a = leftPad(utils.numberToHexUnpadded(sm2Curve.CURVE.a), 64)
  // const b = leftPad(G.curve.b.toBigInteger().toRadix(16), 64)
  const b = leftPad(utils.numberToHexUnpadded(sm2Curve.CURVE.b), 64)
  // const gx = leftPad(G.getX().toBigInteger().toRadix(16), 64)
  const gx = leftPad(utils.numberToHexUnpadded(sm2Curve.ProjectivePoint.BASE.x), 64)
  // const gy = leftPad(G.getY().toBigInteger().toRadix(16), 64)
  const gy = leftPad(utils.numberToHexUnpadded(sm2Curve.ProjectivePoint.BASE.y), 64)
  let px: string
  let py: string
  if (publicKey.length === 128) {
    px = publicKey.substring(0, 64)
    py = publicKey.substring(64, 128)
  } else {
    // const point = G.curve.decodePointHex(publicKey)!
    const point = sm2Curve.ProjectivePoint.fromHex(publicKey)!
    // px = leftPad(point.getX().toBigInteger().toRadix(16), 64)
    px = leftPad(utils.numberToHexUnpadded(point.x), 64)
    // py = leftPad(point.getY().toBigInteger().toRadix(16), 64)
    py = leftPad(utils.numberToHexUnpadded(point.y), 64)
  }
  const data = hexToArray(userId + a + b + gx + gy + px + py)

  const entl = userId.length * 4

  const z = sm3(utils.concatBytes(new Uint8Array([entl >> 8 & 0x00ff, entl & 0x00ff]), data))

  return z
}

/**
 * sm3杂凑算法
 */
export function getHash(hashHex: string | Uint8Array, publicKey: string, userId = '1234567812345678') {
  const z = getZ(publicKey, userId)
  // e = hash(z || msg)
  return bytesToHex(sm3(utils.concatBytes(z, typeof hashHex === 'string' ? hexToArray(hashHex) : hashHex)))
}

/**
 * 预计算公钥点，可用于提升加密性能
 * @export
 * @param {string} publicKey 公钥
 * @param windowSize 计算窗口大小，默认为 8
 * @returns {ProjPointType<bigint>} 预计算的点
 */
export function precomputePublicKey(publicKey: string, windowSize?: number) {
  const point = sm2Curve.ProjectivePoint.fromHex(publicKey)
  return sm2Curve.utils.precompute(windowSize, point)
}

/**
 * 计算公钥
 */
export function getPublicKeyFromPrivateKey(privateKey: string) {
  const pubKey = sm2Curve.getPublicKey(privateKey, false)
  const pubPad = leftPad(utils.bytesToHex(pubKey), 64)
  return pubPad
}

/**
 * 获取椭圆曲线点
 */
export function getPoint() {
  const keypair = generateKeyPairHex()
  const PA = sm2Curve.ProjectivePoint.fromHex(keypair.publicKey)
  const k = utils.hexToNumber(keypair.privateKey)

  return {
    ...keypair,
    k,
    x1: PA!.x,
  }
}

