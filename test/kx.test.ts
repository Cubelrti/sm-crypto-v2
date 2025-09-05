import { kdf, sm2 } from '@/index'
import { utf8ToArray } from '@/sm3'
import { bytesToHex, hexToBytes } from '@/sm3/utils'
import { bytesToUtf8, concatBytes } from '@noble/ciphers/utils'
import { describe, expect, it } from 'vitest'

describe('key exchange', () => {
  const keyPairA = sm2.generateKeyPairHex()
  const keyPairB = sm2.generateKeyPairHex()
  const ephemeralKeypairA = sm2.generateKeyPairHex()
  const ephemeralKeypairB = sm2.generateKeyPairHex()
  it('agree a key', () => {
    const sharedKeyFromA = sm2.calculateSharedKey(
      keyPairA,
      ephemeralKeypairA,
      keyPairB.publicKey,
      ephemeralKeypairB.publicKey,
      233
    )
    const sharedKeyFromB = sm2.calculateSharedKey(
      keyPairB,
      ephemeralKeypairB,
      keyPairA.publicKey,
      ephemeralKeypairA.publicKey,
      233,
      true
    )
    console.log({
      sharedKeyFromA,
      sharedKeyFromB,
    })
    expect(sharedKeyFromA).toEqual(sharedKeyFromB)
  })
  it('agree a key with user identity', () => {
    const sharedKeyFromA = sm2.calculateSharedKey(
      keyPairA,
      ephemeralKeypairA,
      keyPairB.publicKey,
      ephemeralKeypairB.publicKey,
      233,
      false,
      'alice@yahoo.com',
      'bob@yahoo.com'
    )
    const sharedKeyFromB = sm2.calculateSharedKey(
      keyPairB,
      ephemeralKeypairB,
      keyPairA.publicKey,
      ephemeralKeypairA.publicKey,
      233,
      true,
      'bob@yahoo.com',
      'alice@yahoo.com'
    )
    console.log({
      sharedKeyFromA,
      sharedKeyFromB,
    })
    expect(sharedKeyFromA).toEqual(sharedKeyFromB)
  })

  it('parity check with other crypto lib', () => {
    // Test vectors from https://github.com/Tencent/TencentKonaSMSuite/blob/master/kona-crypto/src/test/java/com/tencent/kona/crypto/provider/SM2KeyAgreementTest.java
    const idHex = '31323334353637383132333435363738'
    const priKeyHex =
      '81EB26E941BB5AF16DF116495F90695272AE2CD63D6C4AE1678418BE48230029'
    const pubKeyHex =
      '04160E12897DF4EDB61DD812FEB96748FBD3CCF4FFE26AA6F6DB9540AF49C942324A7DAD08BB9A459531694BEB20AA489D6649975E1BFCF8C4741B78B4B223007F'
    const tmpPriKeyHex =
      'D4DE15474DB74D06491C440D305E012400990F3E390C7E87153C12DB2EA60BB3'
    const tmpPubKeyHex =
      '0464CED1BDBC99D590049B434D0FD73428CF608A5DB8FE5CE07F15026940BAE40E376629C7AB21E7DB260922499DDB118F07CE8EAAE3E7720AFEF6A5CC062070C0'

    const peerIdHex = '31323334353637383132333435363738'
    const peerPriKeyHex =
      '785129917D45A9EA5437A59356B82338EAADDA6CEB199088F14AE10DEFA229B5'
    const peerPubKeyHex =
      '046AE848C57C53C7B1B5FA99EB2286AF078BA64C64591B8B566F7357D576F16DFBEE489D771621A27B36C5C7992062E9CD09A9264386F3FBEA54DFF69305621C4D'
    const peerTmpPriKeyHex =
      '7E07124814B309489125EAED101113164EBF0F3458C5BD88335C1F9D596243D6'
    const peerTmpPubKeyHex =
      '04ACC27688A6F7B706098BC91FF3AD1BFF7DC2802CDB14CCCCDB0A90471F9BD7072FEDAC0494B2FFC4D6853876C79B8F301C6573AD0AA50F39FC87181E1A1B46FE'

    // Expected shared secret from reference implementation
    const expectedSecret = '6C89347354DE2484C60B4AB1FDE4C6E5'

    // Create key pair objects in the format expected by calculateSharedKey
    const keyPairA = {
      privateKey: priKeyHex,
      publicKey: pubKeyHex,
    }

    const ephemeralKeypairA = {
      privateKey: tmpPriKeyHex,
      publicKey: tmpPubKeyHex,
    }

    const keyPairB = {
      privateKey: peerPriKeyHex,
      publicKey: peerPubKeyHex,
    }

    const ephemeralKeypairB = {
      privateKey: peerTmpPriKeyHex,
      publicKey: peerTmpPubKeyHex,
    }

    // Calculate shared key from A's perspective
    const sharedKeyFromA = sm2.calculateSharedKey(
      keyPairA,
      ephemeralKeypairA,
      keyPairB.publicKey,
      ephemeralKeypairB.publicKey,
      16, // keyLength = 16 bytes (128 bits)
      false,
      bytesToUtf8(hexToBytes(idHex)),
      bytesToUtf8(hexToBytes(peerIdHex))
    )

    // Calculate shared key from B's perspective
    const sharedKeyFromB = sm2.calculateSharedKey(
      keyPairB,
      ephemeralKeypairB,
      keyPairA.publicKey,
      ephemeralKeypairA.publicKey,
      16, // keyLength = 16 bytes (128 bits)
      true,
      bytesToUtf8(hexToBytes(peerIdHex)),
      bytesToUtf8(hexToBytes(idHex))
    )

    console.log({
      sharedKeyFromA,
      sharedKeyFromB,
      expectedSecret,
    })

    // Verify both parties generate the same key
    expect(sharedKeyFromA).toEqual(sharedKeyFromB)

    // // Verify the generated key matches the expected value from the reference implementation
    expect(bytesToHex(sharedKeyFromA).toLowerCase()).toEqual(
      expectedSecret.toLowerCase()
    )
  })
  it('ecdh: sm2 ecdh', () => {
    // demo for ecdh using keyPairA and keyPairB
    const sharedA = sm2.ecdh(keyPairA.privateKey, keyPairB.publicKey)
    console.log('sharedA', bytesToHex(sharedA))
    const sharedB = sm2.ecdh(keyPairB.privateKey, keyPairA.publicKey)
    console.log('sharedB', bytesToHex(sharedB))
    expect(bytesToHex(sharedA)).toEqual(bytesToHex(sharedB))
    const idA = '1234567812345678'
    const idB = '1234567812345678'
    const derived = kdf(
      sharedA,
      16,
      concatBytes(utf8ToArray(idA), utf8ToArray(idB))
    )
    console.log('derived', bytesToHex(derived))
  })
})
