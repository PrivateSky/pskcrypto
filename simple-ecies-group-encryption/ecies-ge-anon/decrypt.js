'use strict';

const mycrypto = require('../lib/crypto')
const common = require('../common')
const libcommon = require('../lib/common')

function checkEncryptedEnvelopeMandatoryProperties(encryptedEnvelope) {
    const mandatoryProperties = ["recvs", "rtag", "ct", "iv", "tag"];
    mandatoryProperties.forEach((property) => {
        if (typeof encryptedEnvelope[property] === 'undefined') {
            throw new Error("Mandatory property " + property + " is missing from input group encrypted envelope");
        }
    })
}

module.exports.decrypt = function (receiverECDHKeyPair, encEnvelope) {

    checkEncryptedEnvelopeMandatoryProperties(encEnvelope)
    libcommon.checkKeyPairMandatoryProperties(receiverECDHKeyPair)
    const receiverECIESInstancesBuffer = Buffer.from(encEnvelope.recvs, mycrypto.encodingFormat)

    const keyBuffer = common.receiverMultiRecipientECIESDecrypt(receiverECDHKeyPair, receiverECIESInstancesBuffer)
    const { symmetricCipherKey, ciphertextMacKey, recvsMacKey } = common.parseKeyBuffer(keyBuffer)

    const ciphertext = Buffer.from(encEnvelope.ct, mycrypto.encodingFormat)
    const tag = Buffer.from(encEnvelope.tag, mycrypto.encodingFormat)
    const iv = Buffer.from(encEnvelope.iv, mycrypto.encodingFormat)
    const recvsTag = Buffer.from(encEnvelope.rtag, mycrypto.encodingFormat)

    if (!mycrypto.KMAC.verifyKMAC(tag,
        ciphertextMacKey,
        Buffer.concat([ciphertext, iv],
            ciphertext.length + iv.length))
    ) {
        throw new Error("Bad ciphertext MAC")
    }
    if (!mycrypto.KMAC.verifyKMAC(recvsTag,
        recvsMacKey,
        receiverECIESInstancesBuffer)
    ) {
        throw new Error("Bad recipient ECIES MAC")
    }

    return mycrypto.symmetricDecrypt(symmetricCipherKey, ciphertext, iv)
}