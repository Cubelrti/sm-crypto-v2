import { run, mark, utils } from 'micro-bmark';
import * as sm from 'sm-crypto'
import * as smV2 from 'sm-crypto-v2'

const msg = 'Hello world~!'
const longMsg = msg.repeat(10000)
const keypair = smV2.sm2.generateKeyPairHex('12345678901234567890')

run(async () => {
  await smV2.sm2.initRNGPool()
  const sig = smV2.sm2.doSignature(msg, keypair.privateKey, { publicKey: keypair.publicKey})

  const RAM = !!process.env.RAM

  const backend = process.env.V2 ? smV2 : sm;
  console.log();
  if (RAM) utils.logMem();
  console.log(`=== sm-crypto${process.env.V2 ? '-v2' : ''} ===`)
  await mark('sm2 generateKeyPair', 100, () => backend.sm2.generateKeyPairHex())
  await mark('sm2 encrypt', 500, () => backend.sm2.doEncrypt(msg, keypair.publicKey));
  await mark('sm2 sign', 500, () => backend.sm2.doSignature(msg, keypair.privateKey, { publicKey: keypair.publicKey}));
  await mark('sm2 verify', 500, () => backend.sm2.doVerifySignature(msg, sig, keypair.publicKey));
  await mark('sm3 hash', 1000, () => backend.default.sm3(longMsg))
  await mark('sm3 hmac', 1000, () => backend.default.sm3(longMsg, { key: 'asdfgh' }))
  await mark('sm4 encrypt', 1000, () => backend.default.sm4.encrypt('hello world! 我是 juneandgreen.'.repeat(1000), '0123456789abcdeffedcba9876543210'))
  await mark('sm4 decrypt', 1000, () => backend.default.sm4.decrypt('681edf34d206965e86b3e94f536e4246002a8a4efa863ccad024ac0300bb40d2'.repeat(1000), '0123456789abcdeffedcba9876543210'))

  if (RAM) utils.logMem();
});
