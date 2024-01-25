/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// Utilities for modular arithmetics and finite fields
import {
  bitMask,
  numberToBytesBE,
  numberToBytesLE,
  bytesToNumberBE,
  bytesToNumberLE,
  ensureBytes,
  validateObject,
} from './utils.js';
import JSBI from 'jsbi';

// prettier-ignore
const _0n = JSBI.BigInt(0), _1n = JSBI.BigInt(1), _2n = JSBI.BigInt(2), _3n = JSBI.BigInt(3);
// prettier-ignore
const _4n = JSBI.BigInt(4), _5n = JSBI.BigInt(5), _8n = JSBI.BigInt(8);
// prettier-ignore
const _9n = JSBI.BigInt(9), _16n = JSBI.BigInt(16);

// Calculates a modulo b
export function mod(a: JSBI, b: JSBI): JSBI {
  const result = JSBI.remainder(a, b);
  return JSBI.greaterThanOrEqual(result, _0n) ? result : JSBI.add(b, result);
}
/**
 * Efficiently raise num to power and do modular division.
 * Unsafe in some contexts: uses ladder, so can expose bigint bits.
 * @example
 * pow(2n, 6n, 11n) // 64n % 11n == 9n
 */
// TODO: use field version && remove
export function pow(num: JSBI, power: JSBI, modulo: JSBI): JSBI {
  if (JSBI.lessThanOrEqual(modulo, _0n) || JSBI.lessThan(power, _0n)) throw new Error('Expected power/modulo > 0');
  if (JSBI.equal(modulo, _1n)) return _0n;
  let res = _1n;
  while (JSBI.greaterThan(power, _0n)) {
    if (JSBI.equal(JSBI.bitwiseAnd(power, _1n), _1n)) res = JSBI.remainder(JSBI.multiply(res, num), modulo);
    num = JSBI.remainder(JSBI.multiply(num, num), modulo);
    power = JSBI.signedRightShift(power, _1n);
  }
  return res;
}

// Does x ^ (2 ^ power) mod p. pow2(30, 4) == 30 ^ (2 ^ 4)
export function pow2(x: JSBI, power: JSBI, modulo: JSBI): JSBI {
  let res = x;
  while (JSBI.greaterThan(power, _0n)) {
    res = JSBI.remainder(JSBI.multiply(res, res), modulo);
    power = JSBI.subtract(power, _1n);
  }
  return res;
}

// Inverses number over modulo
export function invert(number: JSBI, modulo: JSBI): JSBI {
  if (JSBI.equal(number, _0n) || JSBI.lessThanOrEqual(modulo, _0n)) {
    throw new Error(`invert: expected positive integers, got n=${number.toString()} mod=${modulo.toString()}`);
  }
  // Euclidean GCD https://brilliant.org/wiki/extended-euclidean-algorithm/
  let a = mod(number, modulo);
  let b = modulo;
  // prettier-ignore
  let x = _0n, y = _1n, u = _1n, v = _0n;
  while (!JSBI.equal(a, _0n)) {
    const q = JSBI.divide(b, a);
    const r = JSBI.remainder(b, a);
    const m = JSBI.subtract(x, JSBI.multiply(u, q));
    const n = JSBI.subtract(y, JSBI.multiply(v, q));
    // prettier-ignore
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  const gcd = b;
  if (!JSBI.equal(gcd, _1n)) throw new Error('invert: does not exist');
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
export function tonelliShanks(P: JSBI) {
  const legendreC = JSBI.divide(JSBI.subtract(P, _1n), _2n);

  let Q: JSBI, S: JSBI, Z: JSBI;
  for (Q = JSBI.subtract(P, _1n), S = _0n; JSBI.equal(JSBI.remainder(Q, _2n), _0n); Q = JSBI.divide(Q, _2n), S = JSBI.add(S, _1n));

  for (Z = _2n; JSBI.lessThan(Z, P) && !JSBI.equal(pow(Z, legendreC, P), JSBI.subtract(P, _1n)); Z = JSBI.add(Z, _1n));

  if (S === _1n) {
    const p1div4 = JSBI.divide(JSBI.add(P, _1n), _4n);
    return function tonelliFast<T>(Fp: IField<T>, n: T) {
      const root = Fp.pow(n, p1div4);
      if (!Fp.eql(Fp.sqr(root), n)) throw new Error('Cannot find square root');
      return root;
    };
  }

  const Q1div2 = JSBI.divide(JSBI.add(Q, _1n), _2n);
  return function tonelliSlow<T>(Fp: IField<T>, n: T): T {
    if (Fp.pow(n, legendreC) === Fp.neg(Fp.ONE)) throw new Error('Cannot find square root');
    let r = S;
    let g = Fp.pow(Fp.mul(Fp.ONE, Z), Q);
    let x = Fp.pow(n, Q1div2);
    let b = Fp.pow(n, Q);

    while (!Fp.eql(b, Fp.ONE)) {
      if (Fp.eql(b, Fp.ZERO)) return Fp.ZERO;
      let m = _1n;
      for (let t2 = Fp.sqr(b); JSBI.lessThan(m, r); m = JSBI.add(m, _1n)) {
        if (Fp.eql(t2, Fp.ONE)) break;
        t2 = Fp.sqr(t2);
      }
      const ge = Fp.pow(g, JSBI.leftShift(_1n, JSBI.BigInt(
        JSBI.subtract(JSBI.subtract(r, m), _1n)
      )));
      g = Fp.sqr(ge);
      x = Fp.mul(x, ge);
      b = Fp.mul(b, g);
      r = m;
    }
    return x;
  };
}

export function FpSqrt(P: JSBI) {
  if (JSBI.equal(JSBI.remainder(P, _4n), _3n)) {
    const p1div4 = JSBI.divide(JSBI.add(P, _1n), _4n);
    return function sqrt3mod4<T>(Fp: IField<T>, n: T) {
      const root = Fp.pow(n, p1div4);
      if (!Fp.eql(Fp.sqr(root), n)) throw new Error('Cannot find square root');
      return root;
    };
  }

  if (JSBI.equal(JSBI.remainder(P, _8n), _5n)) {
    const c1 = JSBI.divide(JSBI.subtract(P, _5n), _8n);
    return function sqrt5mod8<T>(Fp: IField<T>, n: T) {
      const n2 = Fp.mul(n, _2n);
      const v = Fp.pow(n2, c1);
      const nv = Fp.mul(n, v);
      const i = Fp.mul(Fp.mul(nv, _2n), v);
      const root = Fp.mul(nv, Fp.sub(i, Fp.ONE));
      if (!Fp.eql(Fp.sqr(root), n)) throw new Error('Cannot find square root');
      return root;
    };
  }

  if (JSBI.equal(JSBI.remainder(P, _16n), _9n)) {
    // Logic for P ≡ 9 (mod 16) if necessary
    // Placeholder for additional implementation
  }

  return tonelliShanks(P);
}

// Little-endian check for first LE bit (last BE bit);
export const isNegativeLE = (num: JSBI, modulo: JSBI) => JSBI.equal(JSBI.bitwiseAnd(mod(num, modulo), _1n), _1n);

// Field is not always over prime: for example, Fp2 has ORDER(q)=p^m
export interface IField<T> {
  ORDER: JSBI;
  BYTES: number;
  BITS: number;
  MASK: JSBI;
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
  mul(lhs: T, rhs: T | JSBI): T;
  pow(lhs: T, power: JSBI): T;
  div(lhs: T, rhs: T | JSBI): T;
  // N for NonNormalized (for now)
  addN(lhs: T, rhs: T): T;
  subN(lhs: T, rhs: T): T;
  mulN(lhs: T, rhs: T | JSBI): T;
  sqrN(num: T): T;

  // Optional
  // Should be same as sgn0 function in
  // [RFC9380](https://www.rfc-editor.org/rfc/rfc9380#section-4.1).
  // NOTE: sgn0 is 'negative in LE', which is same as odd. And negative in LE is kinda strange definition anyway.
  isOdd?(num: T): boolean; // Odd instead of even since we have it for Fp2
  // legendre?(num: T): T;
  pow(lhs: T, power: JSBI): T;
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
export function FpPow<T>(f: IField<T>, num: T, power: JSBI): T {
  if (JSBI.lessThan(power, _0n)) throw new Error('Expected power > 0');
  if (JSBI.equal(power, _0n)) return f.ONE;
  if (JSBI.equal(power, _1n)) return num;
  let p = f.ONE;
  let d = num;
  while (JSBI.greaterThan(power, _0n)) {
    if (JSBI.equal(JSBI.bitwiseAnd(power, _1n), _1n)) p = f.mul(p, d);
    d = f.sqr(d);
    power = JSBI.signedRightShift(power, _1n);
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

export function FpDiv<T>(f: IField<T>, lhs: T, rhs: T | JSBI): T {
  return f.mul(lhs, rhs instanceof JSBI ? invert(rhs, f.ORDER) : f.inv(rhs));
}

// This function returns True whenever the value x is a square in the field F.
export function FpIsSquare<T>(f: IField<T>) {
  const legendreConst = JSBI.divide(JSBI.subtract(f.ORDER, _1n), _2n); // Integer arithmetic
  return (x: T): boolean => {
    const p = f.pow(x, legendreConst);
    return f.eql(p, f.ZERO) || f.eql(p, f.ONE);
  };
}

// CURVE.n lengths
export function nLength(n: JSBI, nBitLength?: number) {
  // Bit size, byte size of CURVE.n
  const _nBitLength = nBitLength !== undefined ? nBitLength : n.toString(2).length;
  const nByteLength = Math.ceil(_nBitLength / 8);
  return { nBitLength: _nBitLength, nByteLength };
}

type FpField = IField<JSBI> & Required<Pick<IField<JSBI>, 'isOdd'>>;
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
  ORDER: JSBI,
  bitLen?: number,
  isLE = false,
  redef: Partial<IField<JSBI>> = {}
): Readonly<FpField> {
  if (JSBI.lessThanOrEqual(ORDER, _0n)) throw new Error(`Expected Field ORDER > 0, got ${ORDER.toString()}`);
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
      if (!(num instanceof JSBI))
        throw new Error(`Invalid field element: expected JSBI bigint, got ${typeof num}`);
      return JSBI.greaterThanOrEqual(num, _0n) && JSBI.lessThan(num, ORDER);
    },
    is0: (num) => JSBI.equal(num, _0n),
    isOdd: (num) => JSBI.equal(JSBI.bitwiseAnd(num, _1n), _1n),
    neg: (num) => mod(JSBI.unaryMinus(num), ORDER),
    eql: (lhs, rhs) => JSBI.equal(lhs, rhs),

    sqr: (num) => mod(JSBI.multiply(num, num), ORDER),
    add: (lhs, rhs) => mod(JSBI.add(lhs, rhs), ORDER),
    sub: (lhs, rhs) => mod(JSBI.subtract(lhs, rhs), ORDER),
    mul: (lhs, rhs) => mod(JSBI.multiply(lhs, rhs), ORDER),
    pow: (num, power) => FpPow(f, num, power),
    div: (lhs, rhs) => mod(JSBI.multiply(lhs, invert(rhs, ORDER)), ORDER),

    // Same as above, but doesn't normalize
    sqrN: (num) => JSBI.multiply(num, num),
    addN: (lhs, rhs) => JSBI.add(lhs, rhs),
    subN: (lhs, rhs) => JSBI.subtract(lhs, rhs),
    mulN: (lhs, rhs) => JSBI.multiply(lhs, rhs),

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
  groupOrder: JSBI,
  isLE = false
): JSBI {
  hash = ensureBytes('privateHash', hash);
  const hashLen = hash.length;
  const minLen = nLength(groupOrder).nByteLength + 8;
  if (minLen < 24 || hashLen < minLen || hashLen > 1024)
    throw new Error(`hashToPrivateScalar: expected ${minLen}-1024 bytes of input, got ${hashLen}`);
  const num = isLE ? bytesToNumberLE(hash) : bytesToNumberBE(hash);
  return JSBI.add(mod(num, JSBI.subtract(groupOrder, _1n)), _1n);
}

/**
 * Returns total number of bytes consumed by the field element.
 * For example, 32 bytes for usual 256-bit weierstrass curve.
 * @param fieldOrder number of field elements, usually CURVE.n
 * @returns byte length of field
 */
export function getFieldBytesLength(fieldOrder: JSBI): number {
  if (!(fieldOrder instanceof JSBI)) throw new Error('field order must be JSBI bigint');
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
export function getMinHashLength(fieldOrder: JSBI): number {
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
export function mapHashToField(key: Uint8Array, fieldOrder: JSBI, isLE = false): Uint8Array {
  const len = key.length;
  const fieldLen = getFieldBytesLength(fieldOrder);
  const minLen = getMinHashLength(fieldOrder);
  if (len < 16 || len < minLen || len > 1024)
    throw new Error(`expected ${minLen}-1024 bytes of input, got ${len}`);
  const num = isLE ? bytesToNumberLE(key) : bytesToNumberBE(key);
  const reduced = JSBI.add(mod(num, JSBI.subtract(fieldOrder, _1n)), _1n);
  return isLE ? numberToBytesLE(reduced, fieldLen) : numberToBytesBE(reduced, fieldLen);
}





