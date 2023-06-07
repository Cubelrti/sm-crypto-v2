import { bigintToValue } from "@/sm2/asn1"
import { describe, it, expect } from "vitest"
import { BigInteger } from 'jsbn'

describe('bigintToValue', () => {
    it('should convert a BigInt to a string', () => {
      const input = 12345678901234567890n
      expect(bigintToValue(input)).toEqual('00ab54a98ceb1f0ad2')
    })
  
    it('should handle zero', () => {
      const input = 0n
      expect(bigintToValue(input)).toEqual('00')
    })
  
    it('should handle negative numbers', () => {
      const input = -12345678901234567890n
      expect(bigintToValue(input)).toEqual('ff54ab567314e0f52e')
    })
  })