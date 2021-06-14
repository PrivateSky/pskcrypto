'use strict';

const mycrypto = require('../../crypto')
const ecies = require('../../ecies')
const config = require('../../config')

module.exports.generateKeyBufferParams = function (options) {
    const symmetricCipherKey = mycrypto.getRandomBytes(options.symmetricCipherKeySize)
    const ciphertextMacKey = mycrypto.getRandomBytes(options.macKeySize)
    const recvsMacKey = mycrypto.getRandomBytes(options.macKeySize)
    return {
        symmetricCipherKey,
        ciphertextMacKey,
        recvsMacKey
    }
}

module.exports.senderMultiRecipientECIESEncrypt = function(message, ...receiverECDHPublicKeyArray) {
    let options;
    const lastArg = receiverECDHPublicKeyArray[receiverECDHPublicKeyArray.length - 1];
    if (typeof lastArg === "object" && !Array.isArray(lastArg) && !Buffer.isBuffer(lastArg) && !(lastArg instanceof Uint8Array)) {
        options = receiverECDHPublicKeyArray.pop();
    } else {
        options = {};
    }

    const defaultOpts = config;
    Object.assign(defaultOpts, options);
    options = defaultOpts;

    let eciesInstancesArray = []
    receiverECDHPublicKeyArray.forEach(function (curReceiverECDHPublicKey) {
        eciesInstancesArray.push(ecies.encrypt(curReceiverECDHPublicKey, message, options))
    })
    return Buffer.from(JSON.stringify(eciesInstancesArray))
}
