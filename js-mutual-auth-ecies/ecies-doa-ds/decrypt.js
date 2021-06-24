'use strict';

const mycrypto = require('../crypto')
const common = require('../common')
const config = require('../config')

function checkWrappedMessageMandatoryProperties(wrappedMessage) {
    const mandatoryProperties = ["from_ecsig", "msg", "sig"];
    mandatoryProperties.forEach((property) => {
        if (typeof wrappedMessage[property] === 'undefined') {
            throw new Error("Mandatory property " + property + " is missing from wrapped message");
        }
    })
}

module.exports.decrypt = function (receiverECDHPrivateKey, encEnvelope, options) {
    options = options || {};
    const defaultOpts = config;
    Object.assign(defaultOpts, options);
    options = defaultOpts;
    if (typeof encEnvelope === "string") {
        try{
            encEnvelope = JSON.parse(encEnvelope);
        }   catch (e) {
            throw Error(`Could not parse encEnvelope ${encEnvelope}`);
        }
    }

    if (typeof encEnvelope !== "object") {
        throw Error(`encEnvelope should be an object. Received ${typeof encEnvelope}`);
    }

    common.checkEncryptedEnvelopeMandatoryProperties(encEnvelope);
    const ephemeralPublicKey = $$.Buffer.from(encEnvelope.r, options.encodingFormat)

    const ephemeralKeyAgreement = new mycrypto.ECEphemeralKeyAgreement(options)
    const sharedSecret = ephemeralKeyAgreement.computeSharedSecretFromKeyPair(receiverECDHPrivateKey, ephemeralPublicKey)

    const kdfInput = common.computeKDFInput(ephemeralPublicKey, sharedSecret)
    const { symmetricEncryptionKey, macKey } = common.computeSymmetricEncAndMACKeys(kdfInput, options)

    const ciphertext = $$.Buffer.from(encEnvelope.ct, options.encodingFormat)
    const tag = $$.Buffer.from(encEnvelope.tag, options.encodingFormat)
    const iv = $$.Buffer.from(encEnvelope.iv, options.encodingFormat)

    if (!mycrypto.KMAC.verifyKMAC(tag,
        macKey,
        $$.Buffer.concat([ciphertext, iv],
            ciphertext.length + iv.length), options)
    ) {
        throw new Error("Bad MAC")
    }

    let wrappedMessageObject = JSON.parse(mycrypto.symmetricDecrypt(symmetricEncryptionKey, ciphertext, iv, options).toString())
    checkWrappedMessageMandatoryProperties(wrappedMessageObject)
    const senderECSigVerPublicKey = mycrypto.PublicKeyDeserializer.deserializeECSigVerPublicKey(wrappedMessageObject.from_ecsig)

    if (!mycrypto.verifyDigitalSignature(senderECSigVerPublicKey,
        $$.Buffer.from(wrappedMessageObject.sig, options.encodingFormat),
        sharedSecret, options)) {
        throw new Error("Bad signature")
    }
    return {
        from_ecsig: senderECSigVerPublicKey,
        message: $$.Buffer.from(wrappedMessageObject.msg, options.encodingFormat)
    };
}
