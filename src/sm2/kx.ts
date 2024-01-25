import { field, sm2Curve } from './ec';
import { KeyPair, hexToArray, leftPad } from './utils';
import * as utils from './curves/utils';
import { sm3 } from './sm3';
import { EmptyArray, getZ } from '.';
import JSBI from 'jsbi';


// 用到的常数
const wPow2 = utils.hexToNumber('80000000000000000000000000000000')
const wPow2Sub1 = utils.hexToNumber('7fffffffffffffffffffffffffffffff')

// from sm2 sign part, extracted for code reusable.
function hkdf(z: Uint8Array, keylen: number) {
  let msg = new Uint8Array(keylen)
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
    t = sm3(utils.concatBytes(z, ctShift))
    ct++
    offset = 0
  }
  nextT() // 先生成 Ha1

  for (let i = 0, len = msg.length; i < len; i++) {
    // t = Ha1 || Ha2 || Ha3 || Ha4
    if (offset === t.length) nextT()

    // 输出 stream
    msg[i] = t[offset++] & 0xff
  }
  return msg
}

export function calculateSharedKey(
  keypairA: KeyPair,
  ephemeralKeypairA: KeyPair,
  publicKeyB: string,
  ephemeralPublicKeyB: string,
  sharedKeyLength: number,
  isRecipient = false,
  idA: string = '1234567812345678',
  idB: string = '1234567812345678',
) {
  const RA = sm2Curve.ProjectivePoint.fromHex(ephemeralKeypairA.publicKey)
  const RB = sm2Curve.ProjectivePoint.fromHex(ephemeralPublicKeyB)
  // const PA = sm2Curve.ProjectivePoint.fromHex(keypairA.publicKey) // 用不到
  const PB = sm2Curve.ProjectivePoint.fromHex(publicKeyB)
  let ZA = getZ(keypairA.publicKey, idA)
  let ZB = getZ(publicKeyB, idB)
  if (isRecipient) {
    [ZA, ZB] = [ZB, ZA];
  }
  const rA = utils.hexToNumber(ephemeralKeypairA.privateKey)
  const dA = utils.hexToNumber(keypairA.privateKey)
  // 1.先算 tA
  // 1. Calculating tA
  const x1 = RA.x;
  const x1_ = JSBI.add(wPow2, JSBI.bitwiseAnd(x1, wPow2Sub1));
  const tA = field.add(dA, field.mulN(x1_, rA));

  // 2. Calculating U
  const x2 = RB.x;
  const x2_ = JSBI.add(wPow2, JSBI.bitwiseAnd(x2, wPow2Sub1));
  const U = RB.multiply(x2_).add(PB).multiply(tA);

  // 3. Calculating KDF
  const xU = hexToArray(leftPad(utils.numberToHexUnpadded(U.x), 64));
  const yU = hexToArray(leftPad(utils.numberToHexUnpadded(U.y), 64));
  const KA = hkdf(utils.concatBytes(xU, yU, ZA, ZB), sharedKeyLength)
  return KA
}
