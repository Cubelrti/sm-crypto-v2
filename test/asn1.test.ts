import { bigintToValue } from "@/sm2/asn1"
import bigInt from 'big-integer'
import { describe, it, expect } from "vitest"

describe('bigintToValue', () => {
    it('should convert a BigInt to a string', () => {
      const input = bigInt("12345678901234567890")
      expect(bigintToValue(input)).toEqual('00ab54a98ceb1f0ad2')
    })
  
    it('should handle zero', () => {
      const input = bigInt(0)
      expect(bigintToValue(input)).toEqual('00')
    })
  
    it('should handle negative numbers', () => {
      const input = bigInt("-12345678901234567890")
      expect(bigintToValue(input)).toEqual('ff54ab567314e0f52e')
    })
  })