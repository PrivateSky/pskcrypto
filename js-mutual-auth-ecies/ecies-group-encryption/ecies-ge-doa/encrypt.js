'use strict';

const mycrypto = require('../../crypto')
const common = require('../../common')
const config = require('../../config')
const eciesGEAnon = require('../ecies-ge-anon')

module.exports.encrypt = function (senderECSigningKeyPair, message, ...receiverECDHPublicKeys) {
    let options;
    const lastArg = receiverECDHPublicKeys[receiverECDHPublicKeys.length - 1];
    if (typeof lastArg === "object" && !Array.isArray(lastArg) && !$$.Buffer.isBuffer(lastArg) && !(lastArg instanceof Uint8Array)) {
        options = receiverECDHPublicKeys.pop();
    } else {
        options = {};
    }

    const defaultOpts = config;
    Object.assign(defaultOpts, options);
    options = defaultOpts;

    if (typeof message === "object" && !$$.Buffer.isBuffer(message)) {
        message = JSON.stringify(message);
    }

    if (typeof message === "string") {
        message = $$.Buffer.from(message);
    }

    if (!$$.Buffer.isBuffer(message)) {
        throw new Error('Input message has to be of type Buffer');
    }

    common.checkKeyPairMandatoryProperties(senderECSigningKeyPair);
    receiverECDHPublicKeys.push(options);
    let eciesGEEnvelope = eciesGEAnon.encrypt(message, ...receiverECDHPublicKeys)

    const recvsTagBuffer = $$.Buffer.from(eciesGEEnvelope.rtag, options.encodingFormat)
    const tagBuffer = $$.Buffer.from(eciesGEEnvelope.tag, options.encodingFormat)
    const signature = mycrypto.computeDigitalSignature(senderECSigningKeyPair.privateKey,
        $$.Buffer.concat([recvsTagBuffer, tagBuffer],
            recvsTagBuffer.length + tagBuffer.length), options)

    eciesGEEnvelope.sig = signature.toString(options.encodingFormat)
    eciesGEEnvelope.from_ecsig = mycrypto.PublicKeySerializer.serializeECSigVerPublicKey(senderECSigningKeyPair.publicKey, options)

    return eciesGEEnvelope;
}
