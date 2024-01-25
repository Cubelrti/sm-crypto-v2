import { bigintToValue } from "@/sm2/asn1"
import JSBI from 'jsbi'
import { describe, it, expect } from "vitest"

describe('bigintToValue', () => {
    it('should convert a BigInt to a string', () => {
      const input = JSBI.BigInt("12345678901234567890")
      expect(bigintToValue(input)).toEqual('00ab54a98ceb1f0ad2')
    })
  
    it('should handle zero', () => {
      const input = JSBI.BigInt(0)
      expect(bigintToValue(input)).toEqual('00')
    })
  
    it('should handle negative numbers', () => {
      const input = JSBI.BigInt("-12345678901234567890")
      expect(bigintToValue(input)).toEqual('ff54ab567314e0f52e')
    })
  })