function ECKeyGenerator() {
    const crypto = require('crypto');
    const KeyEncoder = require('./keyEncoder');

    this.generateKeyPair = (namedCurve, callback) => {
        if (typeof namedCurve === "undefined") {
            callback = undefined;
            namedCurve = 'secp256k1';
        } else {
            if (typeof namedCurve === "function") {
                callback = namedCurve;
                namedCurve = 'secp256k1';
            }
        }

        const ec = crypto.createECDH(namedCurve);
        const publicKey = ec.generateKeys();
        const privateKey = ec.getPrivateKey();
        if(callback) {
            callback(undefined, publicKey, privateKey);
        }
        return {publicKey, privateKey};
    };

    this.getPemKeys = (privateKey, publicKey, options) => {
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

    this.getPublicKey = (privateKey, namedCurve) => {
        namedCurve = namedCurve || 'secp256k1';
        const ecdh = crypto.createECDH(namedCurve);
        ecdh.setPrivateKey(privateKey);
        return ecdh.getPublicKey();
    };
}

exports.createECKeyGenerator = () => {
    return new ECKeyGenerator();
};