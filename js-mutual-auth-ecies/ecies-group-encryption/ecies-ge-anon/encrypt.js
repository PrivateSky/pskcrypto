'use strict';

const utils = require('../utils')
const mycrypto = require('../../crypto')
const config = require('../../config')

module.exports.encrypt = function (message, ...receiverECDHPublicKeys) {
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

    if (receiverECDHPublicKeys.length === 0) {
        throw new Error('Need to specify at least one receiver public key')
    }

    receiverECDHPublicKeys.push(options);
    const { symmetricCipherKey, ciphertextMacKey, recvsMacKey } = utils.generateKeyBufferParams(options)
    const multiRecipientECIESBuffer = utils.senderMultiRecipientECIESEncrypt(
        $$.Buffer.concat([symmetricCipherKey, ciphertextMacKey, recvsMacKey],
            symmetricCipherKey.length + ciphertextMacKey.length + recvsMacKey.length),
        ...receiverECDHPublicKeys)

    const iv = mycrypto.getRandomBytes(options.ivSize)
    const ciphertext = mycrypto.symmetricEncrypt(symmetricCipherKey, message, iv, options)
    const tag = mycrypto.KMAC.computeKMAC(ciphertextMacKey,
        $$.Buffer.concat(
            [ciphertext, iv],
            ciphertext.length + iv.length), options
    );
    const recvsTag = mycrypto.KMAC.computeKMAC(recvsMacKey, multiRecipientECIESBuffer, options)

    return {
        recvs: multiRecipientECIESBuffer.toString(options.encodingFormat),
        rtag: recvsTag.toString(options.encodingFormat),
        ct: ciphertext.toString(options.encodingFormat),
        iv: iv.toString(options.encodingFormat),
        tag: tag.toString(options.encodingFormat)
    }
}
