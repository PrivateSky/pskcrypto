'use strict';

const mycrypto = require('../lib/crypto')
const ecies = require('../lib/ecies')

module.exports.generateKeyBufferParams = function () {
    const symmetricCipherKey = mycrypto.getRandomBytes(mycrypto.params.symmetricCipherKeySize)
    const ciphertextMacKey = mycrypto.getRandomBytes(mycrypto.params.macKeySize)
    const recvsMacKey = mycrypto.getRandomBytes(mycrypto.params.macKeySize)
    return {
        symmetricCipherKey,
        ciphertextMacKey,
        recvsMacKey
    }
}

module.exports.senderMultiRecipientECIESEncrypt = function(message, ...receiverECDHPublicKeyArray) {
    let eciesInstancesArray = []
    receiverECDHPublicKeyArray.forEach(function (curReceiverECDHPublicKey) {
        eciesInstancesArray.push(ecies.encrypt(curReceiverECDHPublicKey, message))
    })
    return Buffer.from(JSON.stringify(eciesInstancesArray))
}