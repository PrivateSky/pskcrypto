'use strict';

const mycrypto = require('../lib/crypto')
const libcommon = require('../lib/common')
const eciesGEAnon = require('../ecies-ge-anon')

module.exports.encrypt = function (senderECSigningKeyPair, message, ...receiverECDHPublicKeys) {

    libcommon.checkKeyPairMandatoryProperties(senderECSigningKeyPair)

    let eciesGEEnvelope = eciesGEAnon.encrypt(message, ...receiverECDHPublicKeys)

    const recvsTagBuffer = Buffer.from(eciesGEEnvelope.rtag, mycrypto.encodingFormat)
    const tagBuffer = Buffer.from(eciesGEEnvelope.tag, mycrypto.encodingFormat)
    const signature = mycrypto.computeDigitalSignature(senderECSigningKeyPair.privateKey,
        Buffer.concat([recvsTagBuffer, tagBuffer],
            recvsTagBuffer.length + tagBuffer.length))

    eciesGEEnvelope.sig = signature.toString(mycrypto.encodingFormat)
    eciesGEEnvelope.from_ecsig = mycrypto.PublicKeySerializer.serializeECSigVerPublicKey(senderECSigningKeyPair.publicKey)

    return eciesGEEnvelope;
}