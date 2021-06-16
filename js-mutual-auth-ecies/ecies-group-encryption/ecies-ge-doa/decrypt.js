'use strict';

const mycrypto = require('../../crypto')
const config = require('../../config')
const common = require('../../common')
const eciesGEAnon = require('../ecies-ge-anon')

function checkEncryptedEnvelopeMandatoryProperties(encryptedEnvelope) {
    const mandatoryProperties = ["from_ecsig", "sig"];
    mandatoryProperties.forEach((property) => {
        if (typeof encryptedEnvelope[property] === 'undefined') {
            throw new Error("Mandatory property " + property + " is missing from input encrypted envelope");
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

    let tempGEAnonEnvelope = Object.assign({}, encEnvelope)
    delete tempGEAnonEnvelope.from_ecsig;
    delete tempGEAnonEnvelope.sig;
    const message = eciesGEAnon.decrypt(receiverECDHKeyPair, tempGEAnonEnvelope, options)
    tempGEAnonEnvelope = null;

    const senderECSigVerPublicKey = mycrypto.PublicKeyDeserializer.deserializeECSigVerPublicKey(encEnvelope.from_ecsig, options)

    const recvsTagBuffer = $$.Buffer.from(encEnvelope.rtag, options.encodingFormat)
    const tagBuffer = $$.Buffer.from(encEnvelope.tag, options.encodingFormat)
    const signature = $$.Buffer.from(encEnvelope.sig, options.encodingFormat)
    if (!mycrypto.verifyDigitalSignature(senderECSigVerPublicKey,
        signature,
        $$.Buffer.concat([recvsTagBuffer, tagBuffer],
            recvsTagBuffer.length + tagBuffer.length), options)
    ) {
        throw new Error("Bad signature")
    }

    return {
        from: senderECSigVerPublicKey,
        message: message
    }
}
