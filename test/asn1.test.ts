import { bigintToValue, decodeDer } from "@/sm2/asn1"
import { describe, it, expect } from "vitest"

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

describe('decodeDer', () => {
  it('accepts minimal integers, including a required sign byte', () => {
    expect(decodeDer('300702017F02020080')).toEqual({ r: 127n, s: 128n })
  })

  it.each([
    ['wrong SEQUENCE tag', '3106020101020102'],
    ['wrong R tag', '3006030101020102'],
    ['wrong S tag', '3006020101040102'],
    ['redundant S sign byte', '300702010102020002'],
    ['negative INTEGER', '3006020180020102'],
    ['empty INTEGER', '30050200020102'],
    ['non-minimal SEQUENCE length', '308106020101020102'],
    ['non-minimal INTEGER length', '300702810101020102'],
    ['indefinite SEQUENCE length', '30800201010201020000'],
    ['SEQUENCE length shorter than the input', '3005020101020102'],
    ['SEQUENCE length longer than the input', '3007020101020102'],
    ['truncated INTEGER', '3006020101020202'],
    ['extra data inside the SEQUENCE', '3009020101020102020103'],
    ['odd-length input', '300602010102010'],
    ['nonhexadecimal input', '30060201010201g2'],
    ['trailing whitespace', '3006020101020102  '],
  ])('rejects %s', (_description, input) => {
    expect(() => decodeDer(input)).toThrow(/invalid DER/)
  })
})
