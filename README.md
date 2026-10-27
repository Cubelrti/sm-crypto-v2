# sm-crypto-v2

[![npm version](https://badge.fury.io/js/sm-crypto-v2.svg)](https://www.npmjs.com/package/sm-crypto-v2)
[![status](https://img.shields.io/github/actions/workflow/status/cubelrti/sm-crypto-v2/test.yml?branch=master)](https://github.com/cubelrti/sm-crypto-v2/actions)
[![cov](https://cubelrti.github.io/sm-crypto-v2/badges/coverage.svg)](https://github.com/cubelrti/sm-crypto-v2/actions)

国密算法 sm2、sm3 和 sm4 的 JavaScript 实现。

参数支持 TypedArray，导出 esm/cjs。

For WebAssembly-supported platform, see [sm-crypto-wasm](https://github.com/Cubelrti/sm-crypto-wasm) and its [Online Playground](https://cubelrti.github.io/sm-crypto-wasm/)

## 特性

- ⚡ 基于 [`noble-curves` Abstract API](https://github.com/paulmillr/noble-curves#abstract-api) 重构 SM2，性能提升近4倍。详见 [noble-curves 文档](https://paulmillr.com/posts/noble-secp256k1-fast-ecc/) 
- 📘 使用 TypeScript 实现，提供全面的类型支持
- 🔄 移除原有 `jsbn` 依赖，改用原生 BigInt
- ✔️ 通过全部历史单元测试，包括 SM2、SM3 和 SM4
- 🎲 自动选择最优的安全随机数实现，避免使用 `Math.random()` 和 `Date.now()` 进行模拟
- 📚 同时导出 ES Module 和 CommonJS 两种格式，可按需使用
- 🔑 提供 SM2 密钥交换 API
- 🔒 提供 SM4 GCM 模式加密解密能力
- 🎒 未压缩大小 34kb，压缩后 17kb

## 安装

```bash
npm install --save sm-crypto-v2
```

## 2.0 迁移

| 行为 | 1.16.0 兼容版本 | 2.0.0 |
| --- | --- | --- |
| SM2 签名与验签的默认杂凑 | 默认关闭；原始消息应显式使用 `hash: true` | 默认开启；旧协议与预计算摘要显式使用 `hash: false` |
| CBC/GCM 省略 IV | 保留已弃用的全零 IV，仍有重用风险 | 抛出错误，必须显式传入 IV |
| GCM 数组加密输出 | 仅 `outputTag: true` 返回 `{ output, tag }` | 始终返回 `{ output, tag }` |
| GCM 解密认证标签 | 必填且校验 | 必填且校验 |

需要保留上游 sm-crypto 默认行为的用户可安装 `sm-crypto-v2@1`（1.16.0）。两个版本均包含 GCM 标签认证、密钥检查与计数器修复；1.x 的默认 SM2 不杂凑和隐式 IV 风险仅在 2.0 中通过更改默认行为处理。未指定 SM4 mode 时仍使用 ECB。

## sm2

### 获取密钥对

```js
import { sm2 } from 'sm-crypto-v2'

let keypair = sm2.generateKeyPairHex()

publicKey = keypair.publicKey // 公钥
privateKey = keypair.privateKey // 私钥

// 默认生成公钥 130 位太长，可以压缩公钥到 66 位
const compressedPublicKey = sm2.compressPublicKeyHex(publicKey) // compressedPublicKey 和 publicKey 等价
sm2.comparePublicKeyHex(publicKey, compressedPublicKey) // 判断公钥是否等价

// 自定义随机数，参数会直接透传给 BigInt 构造器
// 注意：开发者使用自定义随机数，需要自行确保传入的随机数符合密码学安全
let keypair2 = sm2.generateKeyPairHex('123123123123123')

// 初始化随机数池，在某些场景下可能会用到
await sm2.initRNGPool()

let verifyResult = sm2.verifyPublicKey(publicKey) // 验证公钥
verifyResult = sm2.verifyPublicKey(compressedPublicKey) // 验证公钥
```

### 加密解密

```js
import { sm2 } from 'sm-crypto-v2'
const cipherMode = 1 // 1 - C1C3C2，0 - C1C2C3，默认为1
// 支持使用 asn1 对加密结果进行编码，在 options 参数中传入 { asn1: true } 即可，默认不开启
let encryptData = sm2.doEncrypt(msgString, publicKey, cipherMode, { asn1: false }) // 加密结果

// 支持使用 asn1 对密文进行解码再解密，在 options 参数中传入 { asn1: true } 即可，默认不开启
let decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode, { asn1: false }) // 解密结果

encryptData = sm2.doEncrypt(msgArray, publicKey, cipherMode) // 加密结果，输入数组
decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode, {output: 'array'}) // 解密结果，输出数组
```

### 签名验签

2.0 默认使用标准 SM2 签名流程，计算 `e = SM3(ZA || message)`，其中 ZA 包含用户身份和公钥。`hash: true` 可省略，默认 userId 为 `1234567812345678`。

兼容 1.x 未杂凑签名或传入预计算的 `SM3(ZA || message)` 摘要时，签名和验签均须显式传入 `{ hash: false }`。摘要应以字节数组传入（字符串始终按 UTF-8 处理）。不要将 `hash: false` 用于新的任意原始消息签名。

```js
import { sm2 } from 'sm-crypto-v2'
// 标准签名 + 生成椭圆曲线点
let sigValueHex = sm2.doSignature(msg, privateKey) // 签名
let verifyResult = sm2.doVerifySignature(msg, sigValueHex, publicKey) // 验签结果

// 标准签名，使用预计算点
let sigValueHex2 = sm2.doSignature(msg, privateKey, {
    pointPool: [sm2.getPoint(), sm2.getPoint(), sm2.getPoint(), sm2.getPoint()], // 传入事先已生成好的椭圆曲线点，可加快签名速度
}) // 签名
let verifyResult2 = sm2.doVerifySignature(msg, sigValueHex2, publicKey) // 验签结果

// 标准签名 + der编解码
let sigValueHex3 = sm2.doSignature(msg, privateKey, {
    der: true,
}) // 签名
let verifyResult3 = sm2.doVerifySignature(msg, sigValueHex3, publicKey, {
    der: true,
}) // 验签结果

// 显式开启 sm3 杂凑，与 2.0 默认行为一致
let sigValueHex4 = sm2.doSignature(msg, privateKey, {
    hash: true,
}) // 签名
let verifyResult4 = sm2.doVerifySignature(msg, sigValueHex4, publicKey, {
    hash: true,
}) // 验签结果

// 标准签名，传入公钥以省去公钥推导
let sigValueHex5 = sm2.doSignature(msg, privateKey, {
    hash: true,
    publicKey, // 必须与 privateKey 对应
})
let verifyResult5 = sm2.doVerifySignature(msg, sigValueHex5, publicKey, {
    hash: true,
    publicKey,
})

// 标准签名 + 传入公钥 + 自定义 userId（UTF-8 编码后长度小于 8192 字节）
// 默认 userId 值为 1234567812345678
let sigValueHex6 = sm2.doSignature(msgString, privateKey, {
    hash: true,
    publicKey,
    userId: 'testUserId',
})
let verifyResult6 = sm2.doVerifySignature(msgString, sigValueHex6, publicKey, {
    hash: true,
    userId: 'testUserId',
})
```

### 获取椭圆曲线点

```js
import { sm2 } from 'sm-crypto-v2'
let point = sm2.getPoint() // 获取一个椭圆曲线点，可在sm2签名时传入
```

### 预计算公钥

```js
import { sm2 } from 'sm-crypto-v2'
let keypair = sm2.generateKeyPairHex()

const precomputedPublicKey = sm2.precomputePublicKey(keypair.publicKey)
// 加密和验签可以传入预计算后的点
let encryptData = sm2.doEncrypt(msgString, precomputedPublicKey, cipherMode) // 加密结果
let verifyResult4 = sm2.doVerifySignature(msg, sigValueHex4, precomputedPublicKey, {
    hash: true,
}) // 验签结果

```

### ECDH 密钥协商

```js
import { sm2 } from 'sm-crypto-v2'

const keyPairA = sm2.generateKeyPairHex() // A 的密钥对
const keyPairB = sm2.generateKeyPairHex() // B 的密钥对

// A 使用自己的私钥和 B 的公钥计算共享密钥
const sharedSecretA = sm2.ecdh(keyPairA.privateKey, keyPairB.publicKey)

// B 使用自己的私钥和 A 的公钥计算共享密钥
const sharedSecretB = sm2.ecdh(keyPairB.privateKey, keyPairA.publicKey)

// sharedSecretA === sharedSecretB => true
```

> 注意：`sm2.ecdh` 是简单的椭圆曲线 Diffie-Hellman 密钥协商，适用于无长期公钥场景，没有不可抵赖性。如需更复杂的密钥交换（带临时密钥对和身份信息），请使用下面的 `sm2.calculateSharedKey`（国密标准）。


### 密钥交换

```js
import { sm2 } from 'sm-crypto-v2'

const keyPairA = sm2.generateKeyPairHex() // A 的秘钥对
const keyPairB = sm2.generateKeyPairHex() // B 的秘钥对
const ephemeralKeypairA = sm2.generateKeyPairHex() // A 的临时秘钥对
const ephemeralKeypairB = sm2.generateKeyPairHex() // B 的临时秘钥对

// 无身份的密钥交换
// A 所需参数：A 的秘钥对，A 的临时秘钥对，B 的公钥，B 的临时秘钥公钥，长度，是否为接收方（默认为 false）
const sharedKeyFromA = sm2.calculateSharedKey(keyPairA, ephemeralKeypairA, keyPairB.publicKey, ephemeralKeypairB.publicKey, 233)
// B 所需参数：B 的秘钥对，B 的临时秘钥对，A 的公钥，A 的临时秘钥公钥，长度，是否为接收方（默认为 false）
const sharedKeyFromB = sm2.calculateSharedKey(keyPairB, ephemeralKeypairB, keyPairA.publicKey, ephemeralKeypairA.publicKey, 233, true)

// 带身份的密钥交换
// A 所需参数：A 的秘钥对，A 的临时秘钥对，B 的公钥，B 的临时秘钥公钥，长度，是否为接收方（默认为 false），A 的身份，B 的身份
const sharedKeyFromA = sm2.calculateSharedKey(keyPairA, ephemeralKeypairA, keyPairB.publicKey, ephemeralKeypairB.publicKey, 233, false, 'alice@yahoo.com', 'bob@yahoo.com')
// B 所需参数：B 的秘钥对，B 的临时秘钥对，A 的公钥，A 的临时秘钥公钥，长度，是否为接收方（默认为 false），B 的身份，A 的身份
const sharedKeyFromB = sm2.calculateSharedKey(keyPairB, ephemeralKeypairB, keyPairA.publicKey, ephemeralKeypairA.publicKey, 233, true, 'bob@yahoo.com', 'alice@yahoo.com')

// expect(sharedKeyFromA).toEqual(sharedKeyFromB) => true
```


## sm3

```js
import { sm3, kdf } from 'sm-crypto-v2'
let hashData = sm3('abc') // 杂凑

// hmac
hashData = sm3('abc', {
    key: 'daac25c1512fe50f79b0e4526b93f5c0e1460cef40b6dd44af13caec62e8c60e0d885f3c6d6fb51e530889e6fd4ac743a6d332e68a0f2a3923f42585dceb93e9', // 要求为 16 进制串或字节数组
})

// kdf，注意这是 GM/T 0003-2012 中的 SM3 KDF（密钥派生函数），不是 RFC5869 的 HKDF
kdfData = kdf('abc', 32 /* 输出长度 */)
```

### HKDF (基于 SM3)

```js
import { hkdf } from 'sm-crypto-v2'

const ikm = 'input keying material' // 输入密钥材料，可以为字符串或字节数组
const salt = 'random salt' // 可选，盐值
const info = 'context info' // 可选，上下文信息
const length = 32 // 输出长度（字节）

const derivedKey = hkdf(ikm, salt, info, length) // 返回 Uint8Array
```

> 注意：这是 RFC 5869 定义的 HKDF，使用 SM3 作为底层哈希函数，与上面的 `kdf` 不同。

## sm4

CBC/GCM 加密和解密均必须显式传入 `iv`，不再使用默认全零 IV。CBC 的 IV 必须为 16 字节，每次加密都应使用密码学安全随机数生成新的不可预测 IV；GCM 推荐使用 12 字节 nonce，同一密钥下绝不能重复。调用方负责生成、保存并与密文一起传输 IV/nonce；解密时传入加密时使用的值。

GCM 解密必须传入完整的 16 字节 `tag`，认证通过后才返回明文。GCM 加密始终返回 `{ output, tag }`，包括 `output: 'array'`，`outputTag` 已弃用且不再影响输出。key、iv、tag 等十六进制参数必须为合法的偶数长度十六进制字符串。未指定 mode 时仍使用 ECB。

### 加密

```js
import { sm4 } from 'sm-crypto-v2'
const msg = 'hello world! 我是 juneandgreen.' // 可以为 utf8 串或字节数组
const key = '0123456789abcdeffedcba9876543210' // 可以为 16 进制串或字节数组，要求为 128 比特

let encryptData = sm4.encrypt(msg, key) // 加密，默认输出 16 进制字符串，默认使用 pkcs#7 填充（传 pkcs#5 也会走 pkcs#7 填充）
let encryptData = sm4.encrypt(msg, key, {padding: 'none'}) // 加密，不使用 padding
let encryptData = sm4.encrypt(msg, key, {padding: 'none', output: 'array'}) // 加密，不使用 padding，输出为字节数组
// 以下随机数示例适用于提供 Web Crypto 的环境；其他环境请使用平台的 CSPRNG。
const cbcIv = crypto.getRandomValues(new Uint8Array(16)) // 每次加密重新生成
let encryptData = sm4.encrypt(msg, key, {mode: 'cbc', iv: cbcIv}) // 保存 cbcIv 用于解密
const iv = crypto.getRandomValues(new Uint8Array(12)) // 每次 GCM 加密重新生成，不能在同一密钥下重复
const associatedData = new Uint8Array(0) // 可选的附加认证数据，加解密时须一致
const gcmResult = sm4.encrypt(msg, key, {
    mode: 'gcm', // gcm 模式，必填 iv, 可选 aad
    iv,
    associatedData,
    output: 'string',
}) // 输出格式 { output: T; tag: T; } T 为 string/Uint8Array，保存 iv、output 和 tag

```

### 解密

```js
import { sm4 } from 'sm-crypto-v2'
const encryptData = '0e395deb10f6e8a17e17823e1fd9bd98a1bff1df508b5b8a1efb79ec633d1bb129432ac1b74972dbe97bab04f024e89c' // 可以为 16 进制串或字节数组
const key = '0123456789abcdeffedcba9876543210' // 可以为 16 进制串或字节数组，要求为 128 比特

let decryptData = sm4.decrypt(encryptData, key) // 解密，默认输出 utf8 字符串，默认使用 pkcs#7 填充（传 pkcs#5 也会走 pkcs#7 填充）
let decryptData = sm4.decrypt(encryptData, key, {padding: 'none'}) // 解密，不使用 padding
let decryptData = sm4.decrypt(encryptData, key, {padding: 'none', output: 'array'}) // 解密，不使用 padding，输出为字节数组
let decryptData = sm4.decrypt(encryptData, key, {mode: 'cbc', iv: cbcIv}) // 使用加密时保存的 CBC IV
let decryptData = sm4.decrypt(gcmResult.output, key, { // gcmResult 为 GCM 加密返回的 { output, tag }
    mode: 'gcm', // gcm 模式必填 iv tag, 可选 aad
    iv,
    associatedData,
    tag: gcmResult.tag, // 必填，加密时保存的完整 16 字节认证标签
    output: 'array'
}) // 输出格式 string/Uint8Array
```

## 其他实现

* 原 js 版本：[https://github.com/JuneAndGreen/sm-crypto](https://github.com/JuneAndGreen/sm-crypto)
* 小程序移植版：[https://github.com/wechat-miniprogram/sm-crypto](https://github.com/wechat-miniprogram/sm-crypto)
* java 实现（感谢 @antherd 提供）：[https://github.com/antherd/sm-crypto](https://github.com/antherd/sm-crypto)
* dart 实现（感谢 @luckykellan 提供）：[https://github.com/luckykellan/dart_sm](https://github.com/luckykellan/dart_sm)

## 性能

CPU: Apple M2

| Operation          | sm-crypto    | sm-crypto-v2 | Difference (in times) |
|--------------------|--------------|--------------|-----------------------|
| sm2 generateKeyPair| 148 ops/sec  | 3,452 ops/sec| 23.3x                 |
| sm2 encrypt        | 76 ops/sec   | 304 ops/sec  | 4x                    |
| sm2 sign           | 150 ops/sec  | 3,829 ops/sec| 25.5x                 |
| sm2 verify         | 76 ops/sec   | 306 ops/sec  | 4x                    |
| sm3 hash           | 322 ops/sec  | 519 ops/sec  | 1.6x                  |
| sm3 hmac           | 244 ops/sec  | 518 ops/sec  | 2.1x                  |
| sm4 encrypt        | 102,009 ops/sec | 102,124 ops/sec | 1x               |
| sm4 decrypt        | 143,430 ops/sec | 237,247 ops/sec | 1.7x             |

内存：

| Metric             | sm-crypto    | sm-crypto-v2 | Difference            |
|--------------------|--------------|--------------|-----------------------|
| RAM (rss)          | 57.9mb       | 57.7mb       | -0.2mb                |
| RAM (heap)         | 16.6mb       | 16.6mb       | 0mb                   |
| RAM (used)         | 10.4mb       | 10.5mb       | +0.1mb                |
| RAM (end - start)  | 83.1mb       | 71.8mb       | -11.3mb               |

## 协议

MIT
