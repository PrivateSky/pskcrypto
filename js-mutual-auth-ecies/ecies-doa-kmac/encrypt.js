'use strict';

const mycrypto = require('../crypto');
const common = require('../common')
const config = require('../config')

function senderMessageWrapAndSerialization(senderECDHPublicKey, message) {
    return JSON.stringify({
        from_ecdh: mycrypto.PublicKeySerializer.serializeECDHPublicKey(senderECDHPublicKey),
        msg: message
    });
}

module.exports.encrypt = function (senderECDHKeyPair, receiverECDHPublicKey, message, options) {
    options = options || {};
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
    common.checkKeyPairMandatoryProperties(senderECDHKeyPair)
    const senderKeyAgreement = new mycrypto.ECEphemeralKeyAgreement(options)
    const senderDerivedSharedSecret = senderKeyAgreement.computeSharedSecretFromKeyPair(senderECDHKeyPair.privateKey, receiverECDHPublicKey)

    const senderAuthMsgEnvelopeSerialized = senderMessageWrapAndSerialization(senderECDHKeyPair.publicKey, message);

    const ephemeralKeyAgreement = new mycrypto.ECEphemeralKeyAgreement(options)
    const ephemeralPublicKey = ephemeralKeyAgreement.generateEphemeralPublicKey()
    const ephemeralSharedSecret = ephemeralKeyAgreement.generateSharedSecretForPublicKey(receiverECDHPublicKey)

    const kdfInput = common.computeKDFInput(ephemeralPublicKey, ephemeralSharedSecret)
    const {symmetricEncryptionKey, macKey} = common.computeSymmetricEncAndMACKeys(kdfInput, options)

    const iv = mycrypto.getRandomBytes(options.ivSize)
    const ciphertext = mycrypto.symmetricEncrypt(symmetricEncryptionKey, senderAuthMsgEnvelopeSerialized, iv, options)
    // **TODO**: This does not seem correct, need to think about it.
    const tag = mycrypto.KMAC.computeKMAC(macKey,
        $$.Buffer.concat([ciphertext, iv, senderDerivedSharedSecret],
            ciphertext.length + iv.length + senderDerivedSharedSecret.length), options
    )

    return common.createEncryptedEnvelopeObject(receiverECDHPublicKey, ephemeralPublicKey, ciphertext, iv, tag, options)
};
