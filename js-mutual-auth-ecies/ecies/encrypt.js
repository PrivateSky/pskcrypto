'use strict';

const mycrypto = require('../crypto')
const common = require('../common')
const config = require('../config');

module.exports.encrypt = function (receiverECDHPublicKey, message, options) {
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

    receiverECDHPublicKey = common.convertKeysToKeyObjects(receiverECDHPublicKey, "public");

    const ephemeralKeyAgreement = new mycrypto.ECEphemeralKeyAgreement(options)
    const ephemeralPublicKey = ephemeralKeyAgreement.generateEphemeralPublicKey()
    const sharedSecret = ephemeralKeyAgreement.generateSharedSecretForPublicKey(receiverECDHPublicKey)

    const kdfInput = common.computeKDFInput(ephemeralPublicKey, sharedSecret)
    const { symmetricEncryptionKey, macKey } = common.computeSymmetricEncAndMACKeys(kdfInput, options)

    const iv = mycrypto.getRandomBytes(options.ivSize)
    const ciphertext = mycrypto.symmetricEncrypt(symmetricEncryptionKey, message, iv, options)
    const tag = mycrypto.KMAC.computeKMAC(macKey,
        $$.Buffer.concat([ciphertext, iv],
            ciphertext.length + iv.length), options
    )

    return common.createEncryptedEnvelopeObject(receiverECDHPublicKey, ephemeralPublicKey, ciphertext, iv, tag, options)
}
