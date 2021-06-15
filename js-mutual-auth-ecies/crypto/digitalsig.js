'use strict';

const crypto = require('crypto');
const config = require('../config');

function computeDigitalSignature(privateECSigningKey, buffer, options) {
    options = options || {};
    const defaultOpts = config;
    Object.assign(defaultOpts, options);
    options = defaultOpts;

    let encodingFormat = options.encodingFormat;
    let signObject = crypto.createSign(config.signAlgorithmName)
    signObject.update(buffer)
    signObject.end();
    return signObject.sign(privateECSigningKey, encodingFormat)

}

function verifyDigitalSignature(publicECVerificationKey, signature, buffer, options) {
    options = options || {};
    const defaultOpts = config;
    Object.assign(defaultOpts, options);
    options = defaultOpts;

    let verifyObject = crypto.createVerify(options.signAlgorithmName)
    verifyObject.update(buffer)
    verifyObject.end()
    return verifyObject.verify(publicECVerificationKey, signature)
}

module.exports = {
    computeDigitalSignature,
    verifyDigitalSignature
}
