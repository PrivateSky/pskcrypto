'use strict';

const common = require('../common')
const mycrypto = require('../lib/crypto')

module.exports.encrypt = function (message, ...receiverECDHPublicKeys) {

    if (!Buffer.isBuffer(message)) {
        throw new Error('Input message has to be of type Buffer')
    }

    if (receiverECDHPublicKeys.length === 0) {
        throw new Error('Need to specify at least one receiver public key')
    }

    const { symmetricCipherKey, ciphertextMacKey, recvsMacKey } = common.generateKeyBufferParams()
    const multiRecipientECIESBuffer = common.senderMultiRecipientECIESEncrypt(
        Buffer.concat([symmetricCipherKey, ciphertextMacKey, recvsMacKey],
            symmetricCipherKey.length + ciphertextMacKey.length + recvsMacKey.length),
        ...receiverECDHPublicKeys)

    const iv = mycrypto.getRandomBytes(mycrypto.params.ivSize)
    const ciphertext = mycrypto.symmetricEncrypt(symmetricCipherKey, message, iv)
    const tag = mycrypto.KMAC.computeKMAC(ciphertextMacKey,
        Buffer.concat(
            [ciphertext, iv],
            ciphertext.length + iv.length)
    )
    const recvsTag = mycrypto.KMAC.computeKMAC(recvsMacKey, multiRecipientECIESBuffer)

    return {
        recvs: multiRecipientECIESBuffer.toString(mycrypto.encodingFormat),
        rtag: recvsTag.toString(mycrypto.encodingFormat),
        ct: ciphertext.toString(mycrypto.encodingFormat),
        iv: iv.toString(mycrypto.encodingFormat),
        tag: tag.toString(mycrypto.encodingFormat)
    }
}