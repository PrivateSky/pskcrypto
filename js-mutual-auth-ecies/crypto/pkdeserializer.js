'use strict';

const crypto = require('crypto')
const config = require('../config');

function PublicKeyDeserializer() {
    this.deserializeECDHPublicKey = (ecdhPublicKeySerialized, options) => {
        options = options || {};
        const defaultOpts = config;
        Object.assign(defaultOpts, options);
        options = defaultOpts;

        let encodingFormat = options.encodingFormat;
        return Buffer.from(ecdhPublicKeySerialized, encodingFormat)
    }

    this.deserializeECSigVerPublicKey = (ecSigVerPublicKeySerialized, options) => {
        options = options || {};
        const defaultOpts = config;
        Object.assign(defaultOpts, options);
        options = defaultOpts;

        let encodingFormat = options.encodingFormat;
        return crypto.createPublicKey({
            key: Buffer.from(ecSigVerPublicKeySerialized, encodingFormat),
            format: options.publicKeyFormat,
            type: options.publicKeyType
        })
    }

}

module.exports = new PublicKeyDeserializer()
