'use strict';

const mycrypto = require('../../crypto')
const utils = require('../utils')
const common = require('../../common')
const config = require('../../config')

function checkEncryptedEnvelopeMandatoryProperties(encryptedEnvelope) {
    const mandatoryProperties = ["recvs", "rtag", "ct", "iv", "tag"];
    mandatoryProperties.forEach((property) => {
        if (typeof encryptedEnvelope[property] === 'undefined') {
            throw new Error("Mandatory property " + property + " is missing from input group encrypted envelope");
        }
    })
}

module.exports.decrypt = function (receiverECDHKeyPair, encEnvelope, options) {
    options = options || {};
    const defaultOpts = config;
    Object.assign(defaultOpts, options);
    options = defaultOpts;

    checkEncryptedEnvelopeMandatoryProperties(encEnvelope)
    common.checkKeyPairMandatoryProperties(receiverECDHKeyPair)
    const receiverECIESInstancesBuffer = $$.Buffer.from(encEnvelope.recvs, options.encodingFormat)

    const keyBuffer = utils.receiverMultiRecipientECIESDecrypt(receiverECDHKeyPair, receiverECIESInstancesBuffer)
    const {symmetricCipherKey, ciphertextMacKey, recvsMacKey} = utils.parseKeyBuffer(keyBuffer)

    const ciphertext = $$.Buffer.from(encEnvelope.ct, options.encodingFormat)
    const tag = $$.Buffer.from(encEnvelope.tag, options.encodingFormat)
    const iv = $$.Buffer.from(encEnvelope.iv, options.encodingFormat)
    const recvsTag = $$.Buffer.from(encEnvelope.rtag, options.encodingFormat)

    if (!mycrypto.KMAC.verifyKMAC(tag,
        ciphertextMacKey,
        $$.Buffer.concat([ciphertext, iv],
            ciphertext.length + iv.length), options)
    ) {
        throw new Error("Bad ciphertext MAC")
    }
    if (!mycrypto.KMAC.verifyKMAC(recvsTag,
        recvsMacKey,
        receiverECIESInstancesBuffer, options)
    ) {
        throw new Error("Bad recipient ECIES MAC")
    }

    return mycrypto.symmetricDecrypt(symmetricCipherKey, ciphertext, iv, options)
}
