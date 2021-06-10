'use strict';

const mycrypto = require('../lib/crypto')
const libcommon = require('../lib/common')
const eciesGEAnon = require('../ecies-ge-anon')

function checkEncryptedEnvelopeMandatoryProperties(encryptedEnvelope) {
    const mandatoryProperties = ["from_ecsig", "sig"];
    mandatoryProperties.forEach((property) => {
        if (typeof encryptedEnvelope[property] === 'undefined') {
            throw new Error("Mandatory property " + property + " is missing from input encrypted envelope");
        }
    })
}

module.exports.decrypt = function (receiverECDHKeyPair, encEnvelope) {

    checkEncryptedEnvelopeMandatoryProperties(encEnvelope)
    libcommon.checkKeyPairMandatoryProperties(receiverECDHKeyPair)

    let tempGEAnonEnvelope = Object.assign({}, encEnvelope)
    delete tempGEAnonEnvelope.from_ecsig;
    delete tempGEAnonEnvelope.sig;
    const message = eciesGEAnon.decrypt(receiverECDHKeyPair, tempGEAnonEnvelope)
    tempGEAnonEnvelope = null;

    const senderECSigVerPublicKey = mycrypto.PublicKeyDeserializer.deserializeECSigVerPublicKey(encEnvelope.from_ecsig)

    const recvsTagBuffer = Buffer.from(encEnvelope.rtag, mycrypto.encodingFormat)
    const tagBuffer = Buffer.from(encEnvelope.tag, mycrypto.encodingFormat)
    const signature = Buffer.from(encEnvelope.sig, mycrypto.encodingFormat)
    if (!mycrypto.verifyDigitalSignature(senderECSigVerPublicKey,
        signature,
        Buffer.concat([recvsTagBuffer, tagBuffer],
            recvsTagBuffer.length + tagBuffer.length))
    ) {
        throw new Error("Bad signature")
    }

    return {
        from: senderECSigVerPublicKey,
        message: message
    }
}