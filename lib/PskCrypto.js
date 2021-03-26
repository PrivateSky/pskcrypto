function PskCrypto() {
    const crypto = require('crypto');
    const utils = require("./utils/cryptoUtils");
    const derAsn1Decoder = require("./utils/DerASN1Decoder");
    const PskEncryption = require("./PskEncryption");


    this.createPskEncryption = (algorithm) => {
        return new PskEncryption(algorithm);
    };

    this.generateKeyPair = (options, callback) => {
        return this.createKeyPairGenerator().generateKeyPair(options, callback);
    };

    this.createKeyPairGenerator = require("./ECKeyGenerator").createECKeyGenerator;

    this.sign = (algorithm, data, privateKey) => {
        if (typeof data === "string") {
            data = $$.Buffer.from(data);
        }

        const sign = crypto.createSign(algorithm);
        sign.update(data);
        sign.end();
        return sign.sign(privateKey);
    };

    this.verify = (algorithm, data, publicKey, signature) => {
        if (typeof data === "string") {
            data = $$.Buffer.from(data);
        }
        const verify = crypto.createVerify(algorithm);
        verify.update(data);
        verify.end();
        return verify.verify(publicKey, signature);
    };

    this.verifyDefault = (data, publicKey, signature) => {
        return this.verify('sha256', data, publicKey, signature);
    }

    this.privateEncrypt = (privateKey, data) => {
        if (typeof data === "string") {
            data = $$.Buffer.from(data);
        }

        return crypto.privateEncrypt(privateKey, data);
    };

    this.privateDecrypt = (privateKey, encryptedData) => {
        if (typeof encryptedData === "string") {
            encryptedData = $$.Buffer.from(encryptedData);
        }

        return crypto.privateDecrypt(privateKey, encryptedData);
    };

    this.publicEncrypt = (publicKey, data) => {
        if (typeof data === "string") {
            data = $$.Buffer.from(data);
        }

        return crypto.publicEncrypt(publicKey, data);
    };

    this.publicDecrypt = (publicKey, encryptedData) => {
        if (typeof encryptedData === "string") {
            encryptedData = $$.Buffer.from(encryptedData);
        }

        return crypto.publicDecrypt(publicKey, encryptedData);
    };

    this.pskHash = function (data, encoding) {
        if ($$.Buffer.isBuffer(data)) {
            return utils.createPskHash(data, encoding);
        }
        if (data instanceof Object) {
            return utils.createPskHash(JSON.stringify(data), encoding);
        }
        return utils.createPskHash(data, encoding);
    };

    this.hash = (algorithm, data, encoding) => {
        if (typeof data === "object" && !$$.Buffer.isBuffer(data)) {
            data = JSON.stringify(data);
        }
        const hash = crypto.createHash(algorithm);
        hash.update(data);
        return hash.digest(encoding);
    };

    this.objectHash = (algorithm, data, encoding) => {
        if(!$$.Buffer.isBuffer(data)){
            const ssutils = require("../signsensusDS/ssutil");
            data = ssutils.dumpObjectForHashing(data);
        }
        return this.hash(algorithm, data, encoding);
    };

    this.pskBase58Encode = function (data) {
        return utils.base58Encode(data);
    }

    this.pskBase58Decode = function (data) {
        return utils.base58Decode(data);
    }

    this.pskHashStream = function (readStream, callback) {
        const pskHash = new utils.PskHash();

        readStream.on('data', (chunk) => {
            pskHash.update(chunk);
        });


        readStream.on('end', () => {
            callback(null, pskHash.digest());
        })
    };

    this.generateSafeUid = function (password, additionalData) {
        password = password || $$.Buffer.alloc(0);
        if (!additionalData) {
            additionalData = $$.Buffer.alloc(0);
        }

        if (!$$.Buffer.isBuffer(additionalData)) {
            additionalData = $$.Buffer.from(additionalData);
        }

        return utils.encode(this.pskHash($$.Buffer.concat([password, additionalData])));
    };

    this.deriveKey = function deriveKey(algorithm, password, iterations) {
        if (arguments.length === 2) {
            if (typeof password === "number") {
                iterations = password
                password = algorithm;
                algorithm = "aes-256-gcm";
            } else {
                iterations = 1000;
            }
        }
        if (typeof password === "undefined") {
            iterations = 1000;
            password = algorithm;
            algorithm = "aes-256-gcm";
        }

        const keylen = utils.getKeyLength(algorithm);
        const salt = utils.generateSalt(password, 32);
        return crypto.pbkdf2Sync(password, salt, iterations, keylen, 'sha256');
    };


    this.randomBytes = (len) => {
        if ($$.environmentType === "browser" /*or.constants.BROWSER_ENVIRONMENT_TYPE*/) {
            let randomArray = new Uint8Array(len);

            return window.crypto.getRandomValues(randomArray);
        } else {
            return crypto.randomBytes(len);
        }
    };

    this.xorBuffers = (...args) => {
        if (args.length < 2) {
            throw Error(`The function should receive at least two arguments. Received ${args.length}`);
        }

        if (args.length === 2) {
            __xorTwoBuffers(args[0], args[1]);
            return args[1];
        }

        for (let i = 0; i < args.length - 1; i++) {
            __xorTwoBuffers(args[i], args[i + 1]);
        }

        function __xorTwoBuffers(a, b) {
            if (!$$.Buffer.isBuffer(a) || !$$.Buffer.isBuffer(b)) {
                throw Error("The argument type should be $$.Buffer.");
            }

            const length = Math.min(a.length, b.length);
            for (let i = 0; i < length; i++) {
                b[i] ^= a[i];
            }

            return b;
        }

        return args[args.length - 1];
    };
    this.decodeDerToASN1ETH = (derSignatureBuffer) => derAsn1Decoder.decodeDERIntoASN1ETH(derSignatureBuffer);
    this.PskHash = utils.PskHash;
}

module.exports = new PskCrypto();


