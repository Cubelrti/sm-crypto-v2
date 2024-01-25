/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// Utilities for modular arithmetics and finite fields
import { BigInteger, isInstance } from 'big-integer';
import {
  bitMask,
  numberToBytesBE,
  numberToBytesLE,
  bytesToNumberBE,
  bytesToNumberLE,
  ensureBytes,
  validateObject,
} from './utils.js';
import bigInt from 'big-integer';

// prettier-ignore
const _0n = bigInt(0), _1n = bigInt(1), _2n = bigInt(2), _3n = bigInt(3);
// prettier-ignore
const _4n = bigInt(4), _5n = bigInt(5), _8n = bigInt(8);
// prettier-ignore
const _9n = bigInt(9), _16n = bigInt(16);

// Calculates a modulo b
export function mod(a: BigInteger, b: BigInteger): BigInteger {
  const result = a.remainder(b);
  return result.greaterOrEquals(_0n) ? result : b.add(result);
}
/**
 * Efficiently raise num to power and do modular division.
 * Unsafe in some contexts: uses ladder, so can expose bigint bits.
 * @example
 * pow(2n, 6n, 11n) // 64n % 11n == 9n
 */
// TODO: use field version && remove
export function pow(num: BigInteger, power: BigInteger, modulo: BigInteger): BigInteger {
  if (modulo.lesserOrEquals(_0n) || power.lesser(_0n)) throw new Error('Expected power/modulo > 0');
  if (modulo.equals(_1n)) return _0n;
  let res = _1n;
  while (power.greater(_0n)) {
    if (power.and(_1n).equals(_1n)) res = res.multiply(num).mod(modulo);
    num = num.multiply(num).mod(modulo);
    power = power.shiftRight(1);
  }
  return res;
}

// Does x ^ (2 ^ power) mod p. pow2(30, 4) == 30 ^ (2 ^ 4)
export function pow2(x: BigInteger, power: BigInteger, modulo: BigInteger): BigInteger {
  let res = x;
  while (power.greater(_0n)) {
    res = res.multiply(res).mod(modulo);
    power = power.minus(_1n);
  }
  return res;
}

// Inverses number over modulo
export function invert(number: BigInteger, modulo: BigInteger): BigInteger {
  if (number.equals(_0n) || modulo.lesserOrEquals(_0n)) {
    throw new Error(`invert: expected positive integers, got n=${number.toString()} mod=${modulo.toString()}`);
  }
  // Euclidean GCD https://brilliant.org/wiki/extended-euclidean-algorithm/
  let a = mod(number, modulo);
  let b = modulo;
  // prettier-ignore
  let x = _0n, y = _1n, u = _1n, v = _0n;
  while (!a.equals(_0n)) {
    const q = b.divide(a);
    const r = b.mod(a);
    const m = x.minus(u.multiply(q));
    const n = y.minus(v.multiply(q));
    // prettier-ignore
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  const gcd = b;
  if (!gcd.equals(_1n)) throw new Error('invert: does not exist');
  return mod(x, modulo);
}

/**
 * Tonelli-Shanks square root search algorithm.
 * 1. https://eprint.iacr.org/2012/685.pdf (page 12)
 * 2. Square Roots from 1; 24, 51, 10 to Dan Shanks
 * Will start an infinite loop if field order P is not prime.
 * @param P field order
 * @returns function that takes field Fp (created from P) and number n
 */
export function tonelliShanks(P: BigInteger) {
  const legendreC = P.minus(_1n).divide(_2n);

  let Q: BigInteger, S: BigInteger, Z: BigInteger;
  for (Q = P.minus(_1n), S = _0n; Q.mod(_2n).equals(_0n); Q = Q.divide(_2n), S = S.add(_1n));

  for (Z = _2n; Z.lesser(P) && !pow(Z, legendreC, P).equals(P.minus(_1n)); Z = Z.add(_1n));

  if (S.equals(_1n)) {
    const p1div4 = P.add(_1n).divide(_4n);
    return function tonelliFast(Fp, n) {
      const root = Fp.pow(n, p1div4);
      if (!Fp.eql(Fp.sqr(root), n)) throw new Error('Cannot find square root');
      return root;
    };
  }

  const Q1div2 = Q.add(_1n).divide(_2n);
  return function tonelliSlow(Fp, n) {
    if (Fp.pow(n, legendreC).equals(Fp.neg(Fp.ONE))) throw new Error('Cannot find square root');
    let r = S;
    let g = Fp.pow(Fp.mul(Fp.ONE, Z), Q);
    let x = Fp.pow(n, Q1div2);
    let b = Fp.pow(n, Q);

    while (!Fp.eql(b, Fp.ONE)) {
      if (Fp.eql(b, Fp.ZERO)) return Fp.ZERO;
      let m = _1n;
      for (let t2 = Fp.sqr(b); m.lesser(r); m = m.add(_1n)) {
        if (Fp.eql(t2, Fp.ONE)) break;
        t2 = Fp.sqr(t2);
      }
      const ge = Fp.pow(g, bigInt(2).pow(
        r.minus(m).minus(_1n)
      ));
      g = Fp.sqr(ge);
      x = Fp.mul(x, ge);
      b = Fp.mul(b, g);
      r = m;
    }
    return x;
  };

}

export function FpSqrt(P: BigInteger) {
  if (P.mod(_4n).equals(_3n)) {
    const p1div4 = P.add(_1n).divide(_4n);
    return function sqrt3mod4(Fp, n) {
      const root = Fp.pow(n, p1div4);
      if (!Fp.eql(Fp.sqr(root), n)) throw new Error('Cannot find square root');
      return root;
    };
  }

  if (P.mod(_8n).equals(_5n)) {
    const c1 = P.minus(_5n).divide(_8n);
    return function sqrt5mod8(Fp, n) {
      const n2 = Fp.mul(n, _2n);
      const v = Fp.pow(n2, c1);
      const nv = Fp.mul(n, v);
      const i = Fp.mul(Fp.mul(nv, _2n), v);
      const root = Fp.mul(nv, Fp.sub(i, Fp.ONE));
      if (!Fp.eql(Fp.sqr(root), n)) throw new Error('Cannot find square root');
      return root;
    };
  }

  if (P.mod(_16n).equals(_9n)) {
    // Logic for P ≡ 9 (mod 16) if necessary
    // Placeholder for additional implementation
  }

  return tonelliShanks(P);
}

// Little-endian check for first LE bit (last BE bit);
export const isNegativeLE = (num: BigInteger, modulo: BigInteger) => mod(num, modulo).and(_1n).equals(_1n);

// Field is not always over prime: for example, Fp2 has ORDER(q)=p^m
export interface IField<T> {
  ORDER: BigInteger;
  BYTES: number;
  BITS: number;
  MASK: BigInteger;
  ZERO: T;
  ONE: T;
  // 1-arg
  create: (num: T) => T;
  isValid: (num: T) => boolean;
  is0: (num: T) => boolean;
  neg(num: T): T;
  inv(num: T): T;
  sqrt(num: T): T;
  sqr(num: T): T;
  // 2-args
  eql(lhs: T, rhs: T): boolean;
  add(lhs: T, rhs: T): T;
  sub(lhs: T, rhs: T): T;
  mul(lhs: T, rhs: T | BigInteger): T;
  pow(lhs: T, power: BigInteger): T;
  div(lhs: T, rhs: T | BigInteger): T;
  // N for NonNormalized (for now)
  addN(lhs: T, rhs: T): T;
  subN(lhs: T, rhs: T): T;
  mulN(lhs: T, rhs: T | BigInteger): T;
  sqrN(num: T): T;

  // Optional
  // Should be same as sgn0 function in
  // [RFC9380](https://www.rfc-editor.org/rfc/rfc9380#section-4.1).
  // NOTE: sgn0 is 'negative in LE', which is same as odd. And negative in LE is kinda strange definition anyway.
  isOdd?(num: T): boolean; // Odd instead of even since we have it for Fp2
  // legendre?(num: T): T;
  pow(lhs: T, power: BigInteger): T;
  invertBatch: (lst: T[]) => T[];
  toBytes(num: T): Uint8Array;
  fromBytes(bytes: Uint8Array): T;
  // If c is False, CMOV returns a, otherwise it returns b.
  cmov(a: T, b: T, c: boolean): T;
}
// prettier-ignore
const FIELD_FIELDS = [
  'create', 'isValid', 'is0', 'neg', 'inv', 'sqrt', 'sqr',
  'eql', 'add', 'sub', 'mul', 'pow', 'div',
  'addN', 'subN', 'mulN', 'sqrN'
] as const;
export function validateField<T>(field: IField<T>) {
  const initial = {
    ORDER: 'bigint',
    MASK: 'bigint',
    BYTES: 'isSafeInteger',
    BITS: 'isSafeInteger',
  } as Record<string, string>;
  const opts = FIELD_FIELDS.reduce((map, val: string) => {
    map[val] = 'function';
    return map;
  }, initial);
  return validateObject(field, opts);
}

// Generic field functions

/**
 * Same as `pow` but for Fp: non-constant-time.
 * Unsafe in some contexts: uses ladder, so can expose bigint bits.
 */
export function FpPow<T>(f: IField<T>, num: T, power: BigInteger): T {
  if (power.lesser(_0n)) throw new Error('Expected power > 0');
  if (power.equals(_0n)) return f.ONE;
  if (power.equals(_1n)) return num;
  let p = f.ONE;
  let d = num;
  while (power.greater(_0n)) {
    if (power.and(_1n).equals(_1n)) p = f.mul(p, d);
    d = f.sqr(d);
    power = power.shiftRight(1);
  }
  return p;
}

/**
 * Efficiently invert an array of Field elements.
 * `inv(0)` will return `undefined` here: make sure to throw an error.
 */
export function FpInvertBatch<T>(f: IField<T>, nums: T[]): T[] {
  const tmp = new Array(nums.length);
  // Walk from first to last, multiply them by each other MOD p
  const lastMultiplied = nums.reduce((acc, num, i) => {
    if (f.is0(num)) return acc;
    tmp[i] = acc;
    return f.mul(acc, num);
  }, f.ONE);
  // Invert last element
  const inverted = f.inv(lastMultiplied);
  // Walk from last to first, multiply them by inverted each other MOD p
  nums.reduceRight((acc, num, i) => {
    if (f.is0(num)) return acc;
    tmp[i] = f.mul(acc, tmp[i]);
    return f.mul(acc, num);
  }, inverted);
  return tmp;
}

export function FpDiv<T>(f: IField<T>, lhs: T, rhs: T | BigInteger): T {
  return f.mul(lhs, isInstance(rhs) ? invert(rhs, f.ORDER) : f.inv(rhs));
}

// This function returns True whenever the value x is a square in the field F.
export function FpIsSquare<T>(f: IField<T>) {
  const legendreConst = f.ORDER.minus(_1n).divide(_2n); // Integer arithmetic
  return (x) => {
    const p = f.pow(x, legendreConst);
    return f.eql(p, f.ZERO) || f.eql(p, f.ONE);
  };
}

// CURVE.n lengths
export function nLength(n: BigInteger, nBitLength?: number) {
  // Bit size, byte size of CURVE.n
  const _nBitLength = nBitLength !== undefined ? nBitLength : n.toString(2).length;
  const nByteLength = Math.ceil(_nBitLength / 8);
  return { nBitLength: _nBitLength, nByteLength };
}

type FpField = IField<BigInteger> & Required<Pick<IField<BigInteger>, 'isOdd'>>;
/**
 * Initializes a finite field over prime. **Non-primes are not supported.**
 * Do not init in loop: slow. Very fragile: always run a benchmark on a change.
 * Major performance optimizations:
 * * a) denormalized operations like mulN instead of mul
 * * b) same object shape: never add or remove keys
 * * c) Object.freeze
 * @param ORDER prime positive bigint
 * @param bitLen how many bits the field consumes
 * @param isLE (def: false) if encoding / decoding should be in little-endian
 * @param redef optional faster redefinitions of sqrt and other methods
 */

export function Field(
  ORDER: BigInteger,
  bitLen?: number,
  isLE = false,
  redef: Partial<IField<BigInteger>> = {}
): Readonly<FpField> {
  if (ORDER.lesserOrEquals(_0n)) throw new Error(`Expected Field ORDER > 0, got ${ORDER.toString()}`);
  const { nBitLength: BITS, nByteLength: BYTES } = nLength(ORDER, bitLen);
  if (BYTES > 2048) throw new Error('Field lengths over 2048 bytes are not supported');
  const sqrtP = FpSqrt(ORDER);
  const f: Readonly<FpField> = Object.freeze({
    ORDER,
    BITS,
    BYTES,
    MASK: bitMask(BITS),
    ZERO: _0n,
    ONE: _1n,
    create: (num) => mod(num, ORDER),
    isValid: (num) => {
      if (!(isInstance(num)))
        throw new Error(`Invalid field element: expected BigInteger, got ${typeof num}`);
      return num.greaterOrEquals(_0n) && num.lesser(ORDER);
    },
    is0: (num) => num.equals(_0n),
    isOdd: (num) => num.and(_1n).equals(_1n),
    neg: (num) => mod(num.negate(), ORDER),
    eql: (lhs, rhs) => lhs.equals(rhs),
    
    sqr: (num) => mod(num.multiply(num), ORDER),
    add: (lhs, rhs) => mod(lhs.add(rhs), ORDER),
    sub: (lhs, rhs) => mod(lhs.subtract(rhs), ORDER),
    mul: (lhs, rhs) => mod(lhs.multiply(rhs), ORDER),
    pow: (num, power) => FpPow(f, num, power),
    div: (lhs, rhs) => mod(lhs.multiply(invert(rhs, ORDER)), ORDER),
    
    // Same as above, but doesn't normalize
    sqrN: (num) => num.multiply(num),
    addN: (lhs, rhs) => lhs.add(rhs),
    subN: (lhs, rhs) => lhs.subtract(rhs),
    mulN: (lhs, rhs) => lhs.multiply(rhs),
    
    inv: (num) => invert(num, ORDER),
    sqrt: redef.sqrt || ((n) => sqrtP(f, n)),
    invertBatch: (lst) => FpInvertBatch(f, lst),
    cmov: (a, b, c) => (c ? b : a),
    toBytes: (num) => (isLE ? numberToBytesLE(num, BYTES) : numberToBytesBE(num, BYTES)),
    fromBytes: (bytes) => {
      if (bytes.length !== BYTES)
        throw new Error(`Fp.fromBytes: expected ${BYTES}, got ${bytes.length}`);
      return isLE ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
    },
  } as FpField);
  return Object.freeze(f);
}

export function FpSqrtOdd<T>(Fp: IField<T>, elm: T) {
  if (!Fp.isOdd) throw new Error(`Field doesn't have isOdd`);
  const root = Fp.sqrt(elm);
  return Fp.isOdd(root) ? root : Fp.neg(root);
}

export function FpSqrtEven<T>(Fp: IField<T>, elm: T) {
  if (!Fp.isOdd) throw new Error(`Field doesn't have isOdd`);
  const root = Fp.sqrt(elm);
  return Fp.isOdd(root) ? Fp.neg(root) : root;
}

/**
 * "Constant-time" private key generation utility.
 * Same as mapKeyToField, but accepts less bytes (40 instead of 48 for 32-byte field).
 * Which makes it slightly more biased, less secure.
 * @deprecated use mapKeyToField instead
 */
export function hashToPrivateScalar(
  hash: string | Uint8Array,
  groupOrder: BigInteger,
  isLE = false
): BigInteger {
  hash = ensureBytes('privateHash', hash);
  const hashLen = hash.length;
  const minLen = nLength(groupOrder).nByteLength + 8;
  if (minLen < 24 || hashLen < minLen || hashLen > 1024)
    throw new Error(`hashToPrivateScalar: expected ${minLen}-1024 bytes of input, got ${hashLen}`);
  const num = isLE ? bytesToNumberLE(hash) : bytesToNumberBE(hash);
  return mod(num, groupOrder.minus(_1n)).add(_1n);
}

/**
 * Returns total number of bytes consumed by the field element.
 * For example, 32 bytes for usual 256-bit weierstrass curve.
 * @param fieldOrder number of field elements, usually CURVE.n
 * @returns byte length of field
 */
export function getFieldBytesLength(fieldOrder: BigInteger): number {
  if (!(isInstance(fieldOrder))) throw new Error('field order must be BigInteger');
  const bitLength = fieldOrder.toString(2).length;
  return Math.ceil(bitLength / 8);
}

/**
 * Returns minimal amount of bytes that can be safely reduced
 * by field order.
 * Should be 2^-128 for 128-bit curve such as P256.
 * @param fieldOrder number of field elements, usually CURVE.n
 * @returns byte length of target hash
 */
export function getMinHashLength(fieldOrder: BigInteger): number {
  const length = getFieldBytesLength(fieldOrder);
  return length + Math.ceil(length / 2);
}

/**
 * "Constant-time" private key generation utility.
 * Can take (n + n/2) or more bytes of uniform input e.g. from CSPRNG or KDF
 * and convert them into private scalar, with the modulo bias being negligible.
 * Needs at least 48 bytes of input for 32-byte private key.
 * https://research.kudelskisecurity.com/2020/07/28/the-definitive-guide-to-modulo-bias-and-how-to-avoid-it/
 * FIPS 186-5, A.2 https://csrc.nist.gov/publications/detail/fips/186/5/final
 * RFC 9380, https://www.rfc-editor.org/rfc/rfc9380#section-5
 * @param hash hash output from SHA3 or a similar function
 * @param groupOrder size of subgroup - (e.g. secp256k1.CURVE.n)
 * @param isLE interpret hash bytes as LE num
 * @returns valid private scalar
 */
export function mapHashToField(key: Uint8Array, fieldOrder: BigInteger, isLE = false): Uint8Array {
  const len = key.length;
  const fieldLen = getFieldBytesLength(fieldOrder);
  const minLen = getMinHashLength(fieldOrder);
  if (len < 16 || len < minLen || len > 1024)
    throw new Error(`expected ${minLen}-1024 bytes of input, got ${len}`);
  const num = isLE ? bytesToNumberLE(key) : bytesToNumberBE(key);
  const reduced = mod(num, fieldOrder.minus(_1n)).add(_1n);
  return isLE ? numberToBytesLE(reduced, fieldLen) : numberToBytesBE(reduced, fieldLen);
}





