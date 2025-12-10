import { sm3 } from '@/sm2/sm3'
import { hkdf as hkdfNoble } from '@noble/hashes/hkdf'
import { Input } from './utils'

export function hkdf(ikm: Input, salt: Input | undefined, info: Input | undefined, length: number) {
  return hkdfNoble(sm3, ikm, salt, info, length)
}