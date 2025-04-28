import { field, sm2Curve } from './ec';
import { KeyPair, hexToArray, leftPad } from './utils';
import * as utils from '@noble/curves/abstract/utils';
import { EmptyArray, getZ } from '.';
import { kdf } from './kdf';

// 用到的常数
const wPow2 = utils.hexToNumber('80000000000000000000000000000000')
const wPow2Sub1 = utils.hexToNumber('7fffffffffffffffffffffffffffffff')

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
  const x1 = RA.x
  // x1_ = 2^w + (x1 & (2^w - 1))
  const x1_ = wPow2 + (x1 & wPow2Sub1)
  // tA = (dA + x1b * rA) mod n
  const tA = field.add(dA, field.mulN(x1_, rA))

  // 2.算 U
  // x2_ = 2^w + (x2 & (2^w - 1))
  const x2 = RB.x
  const x2_ = field.add(wPow2, (x2 & wPow2Sub1))
  // U = [h * tA](PB + x2_ * RB)
  const U = RB.multiply(x2_).add(PB).multiply(tA)

  // 3.算 KDF
  // KA = KDF(xU || yU || ZA || ZB, kLen)
  const xU = hexToArray(leftPad(utils.numberToHexUnpadded(U.x), 64))
  const yU = hexToArray(leftPad(utils.numberToHexUnpadded(U.y), 64))
  const KA = kdf(utils.concatBytes(xU, yU, ZA, ZB), sharedKeyLength)
  return KA
}
