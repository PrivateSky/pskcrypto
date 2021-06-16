const config = require('../config');

function PublicKeySerializer() {
    this.serializeECDHPublicKey = (ecdhPublicKey, options) => {
        options = options || {};
        const defaultOpts =  config;
        Object.assign(defaultOpts, options);
        options = defaultOpts;

        let encodingFormat = options.encodingFormat;
        return ecdhPublicKey.toString(encodingFormat);
    }

    this.serializeECSigVerPublicKey = (ecSigVerPublicKey, options) => {
        options = options || {};
        const defaultOpts = config;
        Object.assign(defaultOpts, options);
        options = defaultOpts;

        let encodingFormat = options.encodingFormat;
        const ecKeyGenerator = require("../../lib/ECKeyGenerator").createECKeyGenerator();
        const derPublicKey = ecKeyGenerator.convertPublicKey(ecSigVerPublicKey, {originalFormat: "pem", outputFormat: "der", encodingFormat});
        return derPublicKey.toString(encodingFormat)
    }
}

module.exports = new PublicKeySerializer()
