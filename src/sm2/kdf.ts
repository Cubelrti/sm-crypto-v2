import * as utils from '@noble/curves/abstract/utils';
import { sm3 } from './sm3';
import { EmptyArray } from '.';
import { utf8ToArray } from '../sm3';

/**
 * SM3 Key derivation function used in SM2 encryption and key exchange, specified in GM/T 0003-2012
 * @param z Input data (string or Uint8Array)
 * @param keylen Desired key length in bytes
 * @returns Derived key as Uint8Array
 */
export function kdf(
  z: string | Uint8Array,
  keylen: number,
  iv?: string | Uint8Array
) {
  // Convert string input to Uint8Array if needed
  z = typeof z === 'string' ? utf8ToArray(z) : z
  const IV =
    iv == null ? EmptyArray : typeof iv === 'string' ? utf8ToArray(iv) : iv

  let msg = new Uint8Array(keylen)
  let ct = 1
  let offset = 0
  let t: Uint8Array = EmptyArray
  const ctShift = new Uint8Array(4)
  const nextT = () => {
    // (1) Hai = hash(z || ct)
    // (2) ct++
    ctShift[0] = (ct >> 24) & 0x00ff
    ctShift[1] = (ct >> 16) & 0x00ff
    ctShift[2] = (ct >> 8) & 0x00ff
    ctShift[3] = ct & 0x00ff
    t = sm3(utils.concatBytes(z, ctShift, IV))
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
