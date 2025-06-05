// prettier-ignore
export type TypedArray = Int8Array | Uint8ClampedArray | Uint8Array |
  Uint16Array | Int16Array | Uint32Array | Int32Array;

const u8a = (a: any): a is Uint8Array => a instanceof Uint8Array
// Cast array to different type
export const u8 = (arr: TypedArray) =>
  new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength)
export const u32 = (arr: TypedArray) =>
  new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4))

// Cast array to view
export const createView = (arr: TypedArray) =>
  new DataView(arr.buffer, arr.byteOffset, arr.byteLength)

// The rotate right (circular right shift) operation for uint32
export const rotr = (word: number, shift: number) =>
  (word << (32 - shift)) | (word >>> shift)

// big-endian hardware is rare. Just in case someone still decides to run hashes:
// early-throw an error because we don't support BE yet.
export const isLE =
  new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44
if (!isLE) throw new Error('Non little-endian hardware is not supported')

const hexes = Array.from({ length: 256 }, (v, i) =>
  i.toString(16).padStart(2, '0')
)
/**
 * @example bytesToHex(Uint8Array.from([0xca, 0xfe, 0x01, 0x23])) // 'cafe0123'
 */
export function bytesToHex(bytes: Uint8Array): string {
  if (!u8a(bytes)) throw new Error('Uint8Array expected')
  // pre-caching improves the speed 6x
  let hex = ''
  for (let i = 0; i < bytes.length; i++) {
    hex += hexes[bytes[i]]
  }
  return hex
}

/**
 * @example hexToBytes('cafe0123') // Uint8Array.from([0xca, 0xfe, 0x01, 0x23])
 */
export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string')
    throw new Error('hex string expected, got ' + typeof hex)
  const len = hex.length
  if (len % 2)
    throw new Error(
      'padded hex string expected, got unpadded hex of length ' + len
    )
  const array = new Uint8Array(len / 2)
  for (let i = 0; i < array.length; i++) {
    const j = i * 2
    const hexByte = hex.slice(j, j + 2)
    const byte = Number.parseInt(hexByte, 16)
    if (Number.isNaN(byte) || byte < 0) throw new Error('Invalid byte sequence')
    array[i] = byte
  }
  return array
}

declare const TextEncoder: typeof globalThis.TextEncoder | undefined
const te = typeof TextEncoder != 'undefined' && /*#__PURE__*/ new TextEncoder()
// typed array slice - allows garbage collector to free original reference,
// while being more compatible than .slice
const slc = (v: Uint8Array, s: number, e?: number) => {
  if (s == null || s < 0) s = 0
  if (e == null || e > v.length) e = v.length
  // can't use .constructor in case user-supplied
  return new Uint8Array(v.subarray(s, e))
}

// from fflate, string to Uint8Array
export function strToU8(str: string): Uint8Array {
  if (te) return te.encode(str)
  const l = str.length
  let ar = new Uint8Array(str.length + (str.length >> 1))
  let ai = 0
  const w = (v: number) => {
    ar[ai++] = v
  }
  for (let i = 0; i < l; ++i) {
    if (ai + 5 > ar.length) {
      const n = new Uint8Array(ai + 8 + ((l - i) << 1))
      n.set(ar)
      ar = n
    }
    let c = str.charCodeAt(i)
    if (c < 128) w(c)
    else if (c < 2048) w(192 | (c >> 6)), w(128 | (c & 63))
    else if (c > 55295 && c < 57344)
      (c = (65536 + (c & (1023 << 10))) | (str.charCodeAt(++i) & 1023)),
        w(240 | (c >> 18)),
        w(128 | ((c >> 12) & 63)),
        w(128 | ((c >> 6) & 63)),
        w(128 | (c & 63))
    else w(224 | (c >> 12)), w(128 | ((c >> 6) & 63)), w(128 | (c & 63))
  }
  return slc(ar, 0, ai)
}

export type Input = Uint8Array | string
/**
 * Normalizes (non-hex) string or Uint8Array to Uint8Array.
 * Warning: when Uint8Array is passed, it would NOT get copied.
 * Keep in mind for future mutable operations.
 */
export function toBytes(data: Input): Uint8Array {
  if (typeof data === 'string') data = strToU8(data)
  if (!u8a(data)) throw new Error(`expected Uint8Array, got ${typeof data}`)
  return data
}

// For runtime check if class implements interface
export abstract class Hash<T extends Hash<T>> {
  abstract blockLen: number // Bytes per block
  abstract outputLen: number // Bytes in output
  abstract update(buf: Input): this
  // Writes digest into buf
  abstract digestInto(buf: Uint8Array): void
  abstract digest(): Uint8Array
  /**
   * Resets internal state. Makes Hash instance unusable.
   * Reset is impossible for keyed hashes if key is consumed into state. If digest is not consumed
   * by user, they will need to manually call `destroy()` when zeroing is necessary.
   */
  abstract destroy(): void
  /**
   * Clones hash instance. Unsafe: doesn't check whether `to` is valid. Can be used as `clone()`
   * when no options are passed.
   * Reasons to use `_cloneInto` instead of clone: 1) performance 2) reuse instance => all internal
   * buffers are overwritten => causes buffer overwrite which is used for digest in some cases.
   * There are no guarantees for clean-up because it's impossible in JS.
   */
  abstract _cloneInto(to?: T): T
  // Safe version that clones internal state
  clone(): T {
    return this._cloneInto()
  }
}

export type CHash = ReturnType<typeof wrapConstructor>

export function wrapConstructor<T extends Hash<T>>(hashCons: () => Hash<T>) {
  const hashC = (msg: Input): Uint8Array =>
    hashCons().update(toBytes(msg)).digest()
  const tmp = hashCons()
  hashC.outputLen = tmp.outputLen
  hashC.blockLen = tmp.blockLen
  hashC.create = () => hashCons()
  return hashC
}
