const base58 = require('./base58');
const base64 = require('./base64');
const keyEncoder = require("../keyEncoder");

const keySizes = [128, 192, 256];
const authenticationModes = ["ocb", "ccm", "gcm"];

function encode(buffer) {
    return buffer.toString('base64')
        .replace(/\+/g, '')
        .replace(/\//g, '')
        .replace(/=+$/, '');
}

function createPskHash(data, encoding) {
    const pskHash = new PskHash();
    pskHash.update(data);
    return pskHash.digest(encoding);
}

function PskHash() {
    const crypto = require('crypto');

    const sha512 = crypto.createHash('sha512');
    const sha256 = crypto.createHash('sha256');

    function update(data) {
        sha512.update(data);
    }

    function digest(encoding) {
        sha256.update(sha512.digest());
        return sha256.digest(encoding);
    }

    return {
        update, digest
    }
}


function generateSalt(inputData, saltLen) {
    const crypto = require('crypto');
    const hash = crypto.createHash('sha512');
    hash.update(inputData);
    const digest = $$.Buffer.from(hash.digest('hex'), 'binary');

    return digest.slice(0, saltLen);
}

function encryptionIsAuthenticated(algorithm) {
    for (const mode of authenticationModes) {
        if (algorithm.includes(mode)) {
            return true;
        }
    }

    return false;
}

function getKeyLength(algorithm) {
    for (const len of keySizes) {
        if (algorithm.includes(len.toString())) {
            return len / 8;
        }
    }

    throw new Error("Invalid encryption algorithm.");
}

function base58Encode(data) {
    return base58.encode(data);
}

function base58Decode(data) {
    return base58.decode(data);
}

function base64Encode(data) {
    return base64.encode(data);
}

function base64Decode(data) {
    return base64.decode(data);
}

const PEM_TYPES = ["PRIVATE KEY", "PUBLIC KEY", "CERTIFICATE"];
const isPemEncoded = (key) => {
    if (typeof key !== "string") {
        return false;
    }

    for (let i = 0; i < PEM_TYPES.length; i++) {
        if (key.includes(PEM_TYPES[i])) {
            return true;
        }
    }

    return false;
}

const convertPemToDer = (str) => {
    const SEP = "-----";
    const slicedValue = str.slice(SEP.length, str.length - SEP.length);
    const firstIndex = slicedValue.indexOf(SEP) + SEP.length;
    const lastIndex = slicedValue.lastIndexOf(SEP);
    return $$.Buffer.from(slicedValue.slice(firstIndex, lastIndex), "base64");
}

const convertDerPrivateKeyToRaw = (privateKey) => {
    const keyEncoder = require("../keyEncoder");
    const asn1PrivateKey = keyEncoder.ECPrivateKeyASN.decode(privateKey, "der");
    return asn1PrivateKey.privateKey;
};

const convertPemPrivateKeyToRaw = (privateKey) => {
    const derPrivateKey = convertPemToDer(privateKey);
    return convertDerPrivateKeyToRaw(derPrivateKey);
};

module.exports = {
    createPskHash,
    encode,
    generateSalt,
    PskHash,
    base58Encode,
    base58Decode,
    getKeyLength,
    encryptionIsAuthenticated,
    base64Encode,
    base64Decode,
    isPemEncoded,
    convertPemToDer,
    convertDerPrivateKeyToRaw,
    convertPemPrivateKeyToRaw
};

