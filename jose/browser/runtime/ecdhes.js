const {encoder, concat, uint32be, lengthAndInput, concatKdf} = require('../lib/buffer_utils.js');
const crypto = require('./webcrypto.js');
const {checkEncCryptoKey} = require('../lib/crypto_key.js');
const digest = require('./digest.js');
const invalidKeyInput = require('../lib/invalid_key_input.js');
 const deriveKey = async (publicKey, privateKey, algorithm, keyLength, apu = new Uint8Array(0), apv = new Uint8Array(0)) => {
    if (!crypto.isCryptoKey(publicKey)) {
        throw new TypeError(invalidKeyInput(publicKey, 'CryptoKey'));
    }
    checkEncCryptoKey(publicKey, 'ECDH-ES');
    if (!crypto.isCryptoKey(privateKey)) {
        throw new TypeError(invalidKeyInput(privateKey, 'CryptoKey'));
    }
    checkEncCryptoKey(privateKey, 'ECDH-ES', 'deriveBits', 'deriveKey');
    const value = concat(lengthAndInput($$.Buffer.from(algorithm)), lengthAndInput(apu), lengthAndInput(apv), uint32be(keyLength));
    if (!privateKey.usages.includes('deriveBits')) {
        throw new TypeError('ECDH-ES private key "usages" must include "deriveBits"');
    }
    const sharedSecret = new Uint8Array(await crypto.subtle.deriveBits({
        name: 'ECDH',
        public: publicKey,
    }, privateKey, Math.ceil(parseInt(privateKey.algorithm.namedCurve.substr(-3), 10) / 8) <<
        3));
    return concatKdf(digest, sharedSecret, keyLength, value);
};
 const generateEpk = async (key) => {
    if (!crypto.isCryptoKey(key)) {
        throw new TypeError(invalidKeyInput(key, 'CryptoKey'));
    }
    return (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: key.algorithm.namedCurve }, true, ['deriveBits'])).privateKey;
};
 const ecdhAllowed = (key) => {
    if (!crypto.isCryptoKey(key)) {
        throw new TypeError(invalidKeyInput(key, 'CryptoKey'));
    }
    return ['P-256', 'P-384', 'P-521'].includes(key.algorithm.namedCurve);
};

module.exports = {
    deriveKey,
    generateEpk,
    ecdhAllowed
}