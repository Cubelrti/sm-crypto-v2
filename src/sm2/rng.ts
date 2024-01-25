// Secure RNG Generator wrapper
// 1. Use native sync API if available
// 2. Use async API and maintain number pool if available
// 3. Throw error if none of above available
// Web: globalThis.crypto
// Node: async import("crypto").webcrypto
// Mini Program: wx.getRandomValues
import globalThis from './globalThis';
declare module wx {
  function getRandomValues(options: {
    length: number;
    success: (res: { randomValues: ArrayBuffer }) => void;
  }): void;
}

const DEFAULT_PRNG_POOL_SIZE = 16384
let prngPool = new Uint8Array(0)
let _syncCrypto: typeof import('crypto')['webcrypto']
export async function initRNGPool() {
  if ('crypto' in globalThis) {
    _syncCrypto = globalThis.crypto
    return // no need to use pooling
  }
  if (prngPool.length > DEFAULT_PRNG_POOL_SIZE / 2) return // there is sufficient number
  // we always populate full pool size
  // since numbers may be consumed during micro tasks.
  if ('wx' in globalThis && 'getRandomValues' in globalThis.wx) {
    prngPool = await new Promise(r => {
      wx.getRandomValues({
        length: DEFAULT_PRNG_POOL_SIZE,
        success(res) {
          r(new Uint8Array(res.randomValues));
        }
      });
    });
  } else {
    // check if node or browser, use webcrypto if available
    try {
      // node 19+ and browser
      if (globalThis.crypto) {
        _syncCrypto = globalThis.crypto
      } else {
        // node below 19
        const crypto = await import(/* webpackIgnore: true */ 'crypto');
        _syncCrypto = crypto.webcrypto
      }
      const array = new Uint8Array(DEFAULT_PRNG_POOL_SIZE);
      _syncCrypto.getRandomValues(array);
      prngPool = array;
    } catch (error) {
      throw new Error('no available csprng, abort.');
    }
  }
}

initRNGPool()

function consumePool(length: number): Uint8Array {
  if (prngPool.length > length) {
    const prng = prngPool.slice(0, length)
    prngPool = prngPool.slice(length)
    initRNGPool()
    return prng
  } else {
    throw new Error('random number pool is not ready or insufficient, prevent getting too long random values or too often.')
  }
}

export function randomBytes(length = 0): Uint8Array {
  const array = new Uint8Array(length);
  if (_syncCrypto) {
    return _syncCrypto.getRandomValues(array);
  } else {
    // no sync crypto available, use async pool
    const result = consumePool(length)
    return result
  }
}