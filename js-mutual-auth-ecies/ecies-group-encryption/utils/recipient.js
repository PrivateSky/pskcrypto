'use strict';

const mycrypto = require('../../crypto')
const common = require('../../common')
const ecies = require('../../ecies')
const config = require('../../config')

module.exports.getRecipientECDHPublicKeysFromEncEnvelope = function (encEnvelope, options) {
    options = options || {};
    const defaultOpts = config;
    Object.assign(defaultOpts, options);
    options = defaultOpts;

    if (encEnvelope.recvs === undefined) {
        throw new Error('Mandatory property recvs not found in encrypted envelope')
    }
    let multiRecipientECIESEnvelopeArray = JSON.parse(Buffer.from(encEnvelope.recvs, options.encodingFormat))
    if (multiRecipientECIESEnvelopeArray.length === 0) {
        throw new Error('Invalid receiver array in encrypted envelope')
    }
    let recipientECDHPublicKeyArray = [];
    multiRecipientECIESEnvelopeArray.forEach(function (curRecipientECIESEnvelope) {
        common.checkEncryptedEnvelopeMandatoryProperties(curRecipientECIESEnvelope)
        let curRecipientECDHPublicKey = common.getDecodedECDHPublicKeyFromEncEnvelope(curRecipientECIESEnvelope, options)
        recipientECDHPublicKeyArray.push(curRecipientECDHPublicKey)
    })
    if (recipientECDHPublicKeyArray.length === 0) {
        throw new Error('Unable to parse any of the receivers\' ECIES instances')
    }
    return recipientECDHPublicKeyArray;
}

function isECIESEnvelopeForInputECDHPublicKey(eciesEnvelope, ecdhPublicKey, options) {
    const ecdhPublicKeyBuffer = Buffer.from(mycrypto.PublicKeySerializer.serializeECDHPublicKey(ecdhPublicKey, options))
    const envelopeECDHPublicKey = Buffer.from(eciesEnvelope.to_ecdh)
    return mycrypto.timingSafeEqual(envelopeECDHPublicKey, ecdhPublicKeyBuffer);
}

module.exports.receiverMultiRecipientECIESDecrypt = function(receiverECDHKeyPair, multiRecipientECIESBuffer, options) {
    options = options || {};
    const defaultOpts = config;
    Object.assign(defaultOpts, options);
    options = defaultOpts;

    let multiRecipientECIESEnvelopeArray = JSON.parse(multiRecipientECIESBuffer)
    if (multiRecipientECIESEnvelopeArray.length === 0) {
        throw new Error("Parsed an empty receivers ECIES instances array")
    }
    let myECIESInstanceFound = false;
    let message;
    multiRecipientECIESEnvelopeArray.forEach(function (curRecipientECIESEnvelope) {
        common.checkEncryptedEnvelopeMandatoryProperties(curRecipientECIESEnvelope)
        if (isECIESEnvelopeForInputECDHPublicKey(curRecipientECIESEnvelope, receiverECDHKeyPair.publicKey, options)) {
            message = ecies.decrypt(receiverECDHKeyPair.privateKey, curRecipientECIESEnvelope, options)
            myECIESInstanceFound = true;
            return;
        }
    })
    if (!myECIESInstanceFound) {
        throw new Error("Unable to decrypt input envelope with input EC key pair")
    }
    return message;
}

module.exports.parseKeyBuffer = function (keyBuffer, options) {
    options = options || {};
    const defaultOpts = config;
    Object.assign(defaultOpts, options);

    options = defaultOpts;
    if (keyBuffer.length !== (options.symmetricCipherKeySize + (2*options.macKeySize))) {
        throw new Error("Invalid length of decrypted key buffer")
    }
    const symmetricCipherKey = keyBuffer.slice(0, options.symmetricCipherKeySize)
    const ciphertextMacKey = keyBuffer.slice(options.symmetricCipherKeySize, options.symmetricCipherKeySize + options.macKeySize)
    const recvsMacKey = keyBuffer.slice(options.symmetricCipherKeySize + options.macKeySize)
    return {
        symmetricCipherKey,
        ciphertextMacKey,
        recvsMacKey
    }
}
