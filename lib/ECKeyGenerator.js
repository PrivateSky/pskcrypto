const crypto = require('crypto');
const KeyEncoder = require('./keyEncoder');

function ECKeyGenerator() {

    this.generateKeyPair = (options) => {
        const defaultOpts = {encoding: 'hex', namedCurve: 'secp256k1'};
        if (typeof options === "undefined") {
            options = {};
        }
        Object.assign(defaultOpts, options);
        options = defaultOpts;

        const result = {};
        const ec = crypto.createECDH(options.namedCurve);
        result.publicKey = ec.generateKeys(options.encoding);
        result.privateKey = ec.getPrivateKey(options.encoding);
        return result;
    };

    this.convertKeys = (privateKey, publicKey, options) => {
        const defaultOpts = {format: 'pem', namedCurve: 'secp256k1'};
        Object.assign(defaultOpts, options);
        options = defaultOpts;

        const result = {};
        const ECPrivateKeyASN = KeyEncoder.ECPrivateKeyASN;
        const SubjectPublicKeyInfoASN = KeyEncoder.SubjectPublicKeyInfoASN;
        const keyEncoder = new KeyEncoder(options.namedCurve);

        const privateKeyObject = keyEncoder.privateKeyObject(privateKey, publicKey);
        const publicKeyObject = keyEncoder.publicKeyObject(publicKey)

        result.privateKey = ECPrivateKeyASN.encode(privateKeyObject, options.format, privateKeyObject.pemOptions);
        result.publicKey = SubjectPublicKeyInfoASN.encode(publicKeyObject, options.format, publicKeyObject.pemOptions);

        return result;
    }
}

exports.createECKeyGenerator = () => {
    return new ECKeyGenerator();
};