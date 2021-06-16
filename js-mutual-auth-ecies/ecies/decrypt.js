'use strict';

const mycrypto = require('../crypto')
const common = require('../common')
const config = require('../config')


module.exports.decrypt = function (receiverECDHPrivateKey, encEnvelope, options) {
    options = options || {};
    const defaultOpts = config;
    Object.assign(defaultOpts, options);
    options = defaultOpts;

    common.checkEncryptedEnvelopeMandatoryProperties(encEnvelope)

    const ephemeralPublicKey = mycrypto.PublicKeyDeserializer.deserializeECDHPublicKey(encEnvelope.r, options)

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

    return mycrypto.symmetricDecrypt(symmetricEncryptionKey, ciphertext, iv, options)
}
