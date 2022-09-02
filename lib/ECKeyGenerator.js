const utils = require("./utils/cryptoUtils");

function ECKeyGenerator() {
    const crypto = require('crypto');
    const KeyEncoder = require('./keyEncoder');
    const utils = require("./utils/cryptoUtils");
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

    this.convertPublicKey = (publicKey, options) => {
        options = options || {};
        options = removeUndefinedPropsInOpt(options)
        const defaultOpts = {originalFormat: 'raw', outputFormat: 'pem', encodingFormat:"hex", namedCurve: 'secp256k1'};
        Object.assign(defaultOpts, options);
        options = defaultOpts;
        const keyEncoder = new KeyEncoder(options.namedCurve);
        return keyEncoder.encodePublic(publicKey, options.originalFormat, options.outputFormat, options.encodingFormat)
    };

    this.convertPrivateKey = (privateKey, options) => {
        options = options || {};
        options = removeUndefinedPropsInOpt(options)
        const defaultOpts = {originalFormat: 'raw', outputFormat: 'pem', namedCurve: 'secp256k1'};
        Object.assign(defaultOpts, options);
        options = defaultOpts;

        switch (options.outputFormat) {
            case "pem":
                return convertPrivateKeyToPem(privateKey, options);
            case "der":
                return convertPrivateKeyToDer(privateKey, options);
            case "raw":
                return convertPrivateKeyToRaw(privateKey, options);
            default:
                throw Error("Invalid private key output format");
        }

    };

    const convertPrivateKeyToPem = (privateKey, options) => {
        switch (options.originalFormat) {
            case "raw":
                const rawPublicKey = this.getPublicKey(privateKey, options.namedCurve);
                const pemPrivateKey = this.getPemKeys(privateKey, rawPublicKey, options).privateKey;
                return pemPrivateKey;
            case "der":
                const rawPrivateKey =  utils.convertDerPrivateKeyToRaw(privateKey);
                const publicKey = this.getPublicKey(privateKey, options.namedCurve);
                return this.getPemKeys(rawPrivateKey, publicKey, options).privateKey;
            case "pem":
                return privateKey;
            default:
                throw Error("Invalid private key format");
        }
    }

    const convertPrivateKeyToDer = (privateKey, options) => {
        switch (options.originalFormat) {
            case "raw":
                const rawPublicKey = this.getPublicKey(privateKey, options.namedCurve);
                const pemPrivateKey = this.getPemKeys(privateKey, rawPublicKey, options).privateKey;
                return utils.convertPemToDer(pemPrivateKey);
            case "der":
                return privateKey;
            case "pem":
                return utils.convertPemToDer(privateKey);
            default:
                throw Error("Invalid private key format");
        }
    }

    const convertPrivateKeyToRaw = (privateKey, options) => {
        switch (options.originalFormat) {
            case "der":
                return utils.convertDerPrivateKeyToRaw(privateKey);
            case "raw":
                return privateKey;
            case "pem":
                const derPrivateKey = utils.convertPemToDer(privateKey);
                return utils.convertDerPrivateKeyToRaw(derPrivateKey);
            default:
                throw Error("Invalid private key format");
        }
    }

    const removeUndefinedPropsInOpt = (options) => {
        if (options) {
            for (let prop in options) {
                if (typeof options[prop] === "undefined") {
                    delete options[prop];
                }
            }
        }

        return options;
    };
}

exports.createECKeyGenerator = () => {
    return new ECKeyGenerator();
};
