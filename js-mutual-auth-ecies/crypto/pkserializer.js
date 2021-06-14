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
        return ecSigVerPublicKey.export({
            type: options.publicKeyType,
            format: options.publicKeyFormat
        }).toString(encodingFormat)
    }
}

module.exports = new PublicKeySerializer()
