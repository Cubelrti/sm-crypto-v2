// import assert from './_assert.js';
import bigInt, { BigInteger } from 'big-integer';
import { Hash, createView, Input, toBytes, wrapConstructor } from '../sm3/utils.js';

const BoolA = (A: number, B: number, C: number) => ((A & B) | (A & C)) | (B & C)
const BoolB = (A: number, B: number, C: number) => ((A ^ B) ^ C)
const BoolC = (A: number, B: number, C: number) => (A & B) | ((~A) & C)
// Polyfill for Safari 14
function setBigUint64(view: DataView, byteOffset: number, value: BigInteger, isLE: boolean): void {
  // if (typeof view.setBigUint64 === 'function') return view.setBigUint64(byteOffset, value, isLE);
  const _32n = bigInt(32);
  const _u32_max = bigInt(0xffffffff);
  const wh = Number((value.shiftRight(_32n)).and(_u32_max));
  const wl = Number(value.and(_u32_max));
  const h = isLE ? 4 : 0;
  const l = isLE ? 0 : 4;
  view.setUint32(byteOffset + h, wh, isLE);
  view.setUint32(byteOffset + l, wl, isLE);
}

/**
 * 循环左移
 */
export function rotl(x: number, n: number) {
  const s = n & 31
  return (x << s) | (x >>> (32 - s))
}

/**
 * 二进制异或运算
 */
function xor(x: Uint8Array, y: Uint8Array) {
  const result = new Uint8Array(x.length)
  for (let i = x.length - 1; i >= 0; i--) result[i] = (x[i] ^ y[i]) & 0xff
  return result
}

/**
 * 压缩函数中的置换函数 P0(X) = X xor (X <<< 9) xor (X <<< 17)
 */
function P0(X: number) {
  return (X ^ rotl(X, 9)) ^ rotl(X, 17)
}

/**
 * 消息扩展中的置换函数 P1(X) = X xor (X <<< 15) xor (X <<< 23)
 */
function P1(X: number) {
  return (X ^ rotl(X, 15)) ^ rotl(X, 23)
}

// from noble-hashes (https://github.com/paulmillr/noble-hashes#hmac)
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */

// Base SHA2 class (RFC 6234)
export abstract class SHA2<T extends SHA2<T>> extends Hash<T> {
  protected abstract process(buf: DataView, offset: number): void;
  protected abstract get(): number[];
  protected abstract set(...args: number[]): void;
  abstract destroy(): void;
  protected abstract roundClean(): void;
  // For partial updates less than block size
  protected buffer: Uint8Array;
  protected view: DataView;
  protected finished = false;
  protected length = 0;
  protected pos = 0;
  protected destroyed = false;

  constructor(
    readonly blockLen: number,
    public outputLen: number,
    readonly padOffset: number,
    readonly isLE: boolean
  ) {
    super();
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
  }
  update(data: Input): this {
    const { view, buffer, blockLen } = this;
    data = toBytes(data);
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      // Fast path: we have at least one block in input, cast it to view and process
      if (take === blockLen) {
        const dataView = createView(data);
        for (; blockLen <= len - pos; pos += blockLen) this.process(dataView, pos);
        continue;
      }
      buffer.set(data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
      }
    }
    this.length += data.length;
    this.roundClean();
    return this;
  }
  digestInto(out: Uint8Array) {
    this.finished = true;
    // Padding
    // We can avoid allocation of buffer for padding completely if it
    // was previously not allocated here. But it won't change performance.
    const { buffer, view, blockLen, isLE } = this;
    let { pos } = this;
    // append the bit '1' to the message
    buffer[pos++] = 0b10000000;
    this.buffer.subarray(pos).fill(0);
    // we have less than padOffset left in buffer, so we cannot put length in current block, need process it and pad again
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      pos = 0;
    }
    // Pad until full block byte with zeros
    for (let i = pos; i < blockLen; i++) buffer[i] = 0;
    // Note: sha512 requires length to be 128bit integer, but length in JS will overflow before that
    // You need to write around 2 exabytes (u64_max / 8 / (1024**6)) for this to happen.
    // So we just write lowest 64 bits of that value.
    setBigUint64(view, blockLen - 8, bigInt(this.length * 8), isLE);
    this.process(view, 0);
    const oview = createView(out);
    const len = this.outputLen;
    // NOTE: we do division by 4 later, which should be fused in single op with modulo by JIT
    if (len % 4) throw new Error('_sha2: outputLen should be aligned to 32bit');
    const outLen = len / 4;
    const state = this.get();
    if (outLen > state.length) throw new Error('_sha2: outputLen bigger than state');
    for (let i = 0; i < outLen; i++) oview.setUint32(4 * i, state[i], isLE);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneInto(to?: T): T {
    to ||= new (this.constructor as any)() as T;
    to.set(...this.get());
    const { blockLen, buffer, length, finished, destroyed, pos } = this;
    to.length = length;
    to.pos = pos;
    to.finished = finished;
    to.destroyed = destroyed;
    if (length % blockLen) to.buffer.set(buffer);
    return to;
  }
}

const IV = new Uint32Array([0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e])
const SM3_W = new Uint32Array(68)
const SM3_M = new Uint32Array(64)

const T1 = 0x79cc4519
const T2 = 0x7a879d8a

class SM3 extends SHA2<SM3> {
  // We cannot use array here since array allows indexing by variable
  // which means optimizer/compiler cannot use registers.
  A = IV[0] | 0;
  B = IV[1] | 0;
  C = IV[2] | 0;
  D = IV[3] | 0;
  E = IV[4] | 0;
  F = IV[5] | 0;
  G = IV[6] | 0;
  H = IV[7] | 0;

  constructor() {
    super(64, 32, 8, false);
  }
  protected get(): [number, number, number, number, number, number, number, number] {
    const { A, B, C, D, E, F, G, H } = this;
    return [A, B, C, D, E, F, G, H];
  }
  // prettier-ignore
  protected set(
    A: number, B: number, C: number, D: number, E: number, F: number, G: number, H: number
  ) {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D | 0;
    this.E = E | 0;
    this.F = F | 0;
    this.G = G | 0;
    this.H = H | 0;
  }
  protected process(view: DataView, offset: number): void {
    // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
    for (let i = 0; i < 16; i++, offset += 4) SM3_W[i] = view.getUint32(offset, false);
    for (let i = 16; i < 68; i++) {
      SM3_W[i] = (P1((SM3_W[i- 16] ^ SM3_W[i - 9]) ^ rotl(SM3_W[i - 3], 15)) ^ rotl(SM3_W[i - 13], 7)) ^ SM3_W[i - 6]
    }
    for (let i = 0; i < 64; i++) {
      SM3_M[i] = SM3_W[i] ^ SM3_W[i + 4]
    }
    // Compression function main loop, 64 rounds
    let { A, B, C, D, E, F, G, H } = this;
    for (let j = 0; j < 64; j++) {
      let small = j >= 0 && j <= 15
      let T = small ? T1 : T2
      let SS1 = rotl(rotl(A, 12) + E + rotl(T, j), 7)
      let SS2 = SS1 ^ rotl(A, 12)

      let TT1 = ((small ? BoolB(A, B, C) : BoolA(A, B, C)) + D + SS2 + SM3_M[j]) | 0
      let TT2 = ((small ? BoolB(E, F, G) : BoolC(E, F, G)) + H + SS1 + SM3_W[j]) | 0

      D = C
      C = rotl(B, 9)
      B = A
      A = TT1
      H = G
      G = rotl(F, 19)
      F = E
      E = P0(TT2)
    }
    // Add the compressed chunk to the current hash value
    A = (A ^ this.A) | 0;
    B = (B ^ this.B) | 0;
    C = (C ^ this.C) | 0;
    D = (D ^ this.D) | 0;
    E = (E ^ this.E) | 0;
    F = (F ^ this.F) | 0;
    G = (G ^ this.G) | 0;
    H = (H ^ this.H) | 0;
    this.set(A, B, C, D, E, F, G, H);
  }
  protected roundClean() {
    SM3_W.fill(0);
  }
  destroy() {
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
    this.buffer.fill(0);
  }
}
export const sm3 = wrapConstructor(() => new SM3());