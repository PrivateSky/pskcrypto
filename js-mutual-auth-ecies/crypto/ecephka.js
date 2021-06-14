'use strict';

const crypto = require('crypto');
const config = require('../config');

class ECEphemeralKeyAgreement {

    constructor(options) {
        options = options || {};
        const defaultOpts = config;
        Object.assign(defaultOpts, options);
        options = defaultOpts;

        this.ecdh = crypto.createECDH(options.curveName);
    }

    generateEphemeralPublicKey = () => {
        return this.ecdh.generateKeys();
    }

    generateSharedSecretForPublicKey = (theirECDHPublicKey) => {
        try {
            this.ecdh.getPublicKey()
        } catch(error) {
            throw new Error('You cannot generate a shared secret for another public key without calling generateEphemeralPublicKey() first')
        }
        return this.ecdh.computeSecret(theirECDHPublicKey);
    }

    computeSharedSecretFromKeyPair = (myECDHPrivateKey, theirECDHPublicKey) => {
        this.ecdh.setPrivateKey(myECDHPrivateKey);
        return this.ecdh.computeSecret(theirECDHPublicKey);
    }
}

module.exports = ECEphemeralKeyAgreement
