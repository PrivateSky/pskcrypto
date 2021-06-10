'use strict';

const mycrypto = require('../lib/crypto')
const libcommon = require('../lib/common')
const ecies = require('../lib/ecies')

module.exports.getRecipientECDHPublicKeysFromEncEnvelope = function (encEnvelope) {
    if (encEnvelope.recvs === undefined) {
        throw new Error('Mandatory property recvs not found in encrypted envelope')
    }
    let multiRecipientECIESEnvelopeArray = JSON.parse(Buffer.from(encEnvelope.recvs, mycrypto.encodingFormat))
    if (multiRecipientECIESEnvelopeArray.length === 0) {
        throw new Error('Invalid receiver array in encrypted envelope')
    }
    let recipientECDHPublicKeyArray = [];
    multiRecipientECIESEnvelopeArray.forEach(function (curRecipientECIESEnvelope) {
        libcommon.checkEncryptedEnvelopeMandatoryProperties(curRecipientECIESEnvelope)
        let curRecipientECDHPublicKey = libcommon.getDecodedECDHPublicKeyFromEncEnvelope(curRecipientECIESEnvelope)
        recipientECDHPublicKeyArray.push(curRecipientECDHPublicKey)
    })
    if (recipientECDHPublicKeyArray.length === 0) {
        throw new Error('Unable to parse any of the receivers\' ECIES instances')
    }
    return recipientECDHPublicKeyArray;
}

function isECIESEnvelopeForInputECDHPublicKey(eciesEnvelope, ecdhPublicKey) {
    const ecdhPublicKeyBuffer = Buffer.from(mycrypto.PublicKeySerializer.serializeECDHPublicKey(ecdhPublicKey))
    const envelopeECDHPublicKey = Buffer.from(eciesEnvelope.to_ecdh)
    return mycrypto.timingSafeEqual(envelopeECDHPublicKey, ecdhPublicKeyBuffer);
}

module.exports.receiverMultiRecipientECIESDecrypt = function(receiverECDHKeyPair, multiRecipientECIESBuffer) {
    let multiRecipientECIESEnvelopeArray = JSON.parse(multiRecipientECIESBuffer)
    if (multiRecipientECIESEnvelopeArray.length === 0) {
        throw new Error("Parsed an empty receivers ECIES instances array")
    }
    let myECIESInstanceFound = false;
    let message;
    multiRecipientECIESEnvelopeArray.forEach(function (curRecipientECIESEnvelope) {
        libcommon.checkEncryptedEnvelopeMandatoryProperties(curRecipientECIESEnvelope)
        if (isECIESEnvelopeForInputECDHPublicKey(curRecipientECIESEnvelope, receiverECDHKeyPair.publicKey)) {
            message = ecies.decrypt(receiverECDHKeyPair.privateKey, curRecipientECIESEnvelope)
            myECIESInstanceFound = true;
            return;
        }
    })
    if (!myECIESInstanceFound) {
        throw new Error("Unable to decrypt input envelope with input EC key pair")
    }
    return message;
}

module.exports.parseKeyBuffer = function (keyBuffer) {
    if (keyBuffer.length != (mycrypto.params.symmetricCipherKeySize + (2*mycrypto.params.macKeySize))) {
        throw new Error("Invalid length of decrypted key buffer")
    }
    const symmetricCipherKey = keyBuffer.slice(0, mycrypto.params.symmetricCipherKeySize)
    const ciphertextMacKey = keyBuffer.slice(mycrypto.params.symmetricCipherKeySize, mycrypto.params.symmetricCipherKeySize + mycrypto.params.macKeySize)
    const recvsMacKey = keyBuffer.slice(mycrypto.params.symmetricCipherKeySize + mycrypto.params.macKeySize)
    return {
        symmetricCipherKey,
        ciphertextMacKey,
        recvsMacKey
    }
}