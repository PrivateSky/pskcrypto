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
        return $$.Buffer.from(ecdhPublicKeySerialized, encodingFormat)
    }

    this.deserializeECSigVerPublicKey = (ecSigVerPublicKeySerialized, options) => {
        options = options || {};
        const defaultOpts = config;
        Object.assign(defaultOpts, options);
        options = defaultOpts;

        let encodingFormat = options.encodingFormat;
        // let publicKey = $$.Buffer.from(ecSigVerPublicKeySerialized, encodingFormat);
        const ecKeyGenerator = require("../../lib/ECKeyGenerator").createECKeyGenerator();
        const publicKey = ecKeyGenerator.convertPublicKey(ecSigVerPublicKeySerialized, {originalFormat: "der", outputFormat: "pem", encodingFormat});
        return publicKey;
    }

}

module.exports = new PublicKeyDeserializer()
