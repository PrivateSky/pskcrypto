'use strict';

const mycrypto = require('../crypto');
const common = require('../common')
const config = require('../config')

function checkWrappedMessageMandatoryProperties(wrappedMessage) {
    const mandatoryProperties = ["from_ecdh", "msg"];
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

    common.checkEncryptedEnvelopeMandatoryProperties(encEnvelope)
    const ephemeralPublicKey = mycrypto.PublicKeyDeserializer.deserializeECDHPublicKey(encEnvelope.r, options)

    const ephemeralKeyAgreement = new mycrypto.ECEphemeralKeyAgreement(options)
    const sharedSecret = ephemeralKeyAgreement.computeSharedSecretFromKeyPair(receiverECDHPrivateKey, ephemeralPublicKey)

    const kdfInput = common.computeKDFInput(ephemeralPublicKey, sharedSecret)
    const { symmetricEncryptionKey, macKey } = common.computeSymmetricEncAndMACKeys(kdfInput, options)

    const ciphertext = $$.Buffer.from(encEnvelope.ct, options.encodingFormat)
    const tag = $$.Buffer.from(encEnvelope.tag, options.encodingFormat)
    const iv = $$.Buffer.from(encEnvelope.iv, options.encodingFormat)

    const wrappedMessageObject = JSON.parse(mycrypto.symmetricDecrypt(symmetricEncryptionKey, ciphertext, iv, options).toString())
    checkWrappedMessageMandatoryProperties(wrappedMessageObject)
    const senderPublicKey = mycrypto.PublicKeyDeserializer.deserializeECDHPublicKey(wrappedMessageObject.from_ecdh, options);

    const senderKeyAgreement = new mycrypto.ECEphemeralKeyAgreement(options)
    const senderDerivedSharedSecret = senderKeyAgreement.computeSharedSecretFromKeyPair(receiverECDHPrivateKey, senderPublicKey)
    // **TODO**: This does not seem correct, need to think about it.
    mycrypto.KMAC.verifyKMAC(tag, macKey,
        $$.Buffer.concat([ciphertext, iv, senderDerivedSharedSecret],
            ciphertext.length + iv.length + senderDerivedSharedSecret.length), options
    )

    return {
        from_ecdh: senderPublicKey,
        message: $$.Buffer.from(wrappedMessageObject.msg, options.encodingFormat)
    };
}
