const subtleAlgorithm = require('./subtle_rsaes.js');
const bogusWebCrypto = require('./bogus.js');
const crypto = require('./webcrypto.js');
const {checkEncCryptoKey} = require('../lib/crypto_key.js');
const checkKeyLength = require('./check_key_length.js');
const invalidKeyInput = require('../lib/invalid_key_input.js');
const encrypt = async (alg, key, cek) => {
    if (!crypto.isCryptoKey(key)) {
        throw new TypeError(invalidKeyInput(key, 'CryptoKey'));
    }
    checkEncCryptoKey(key, alg, 'encrypt', 'wrapKey');
    checkKeyLength(alg, key);
    if (key.usages.includes('encrypt')) {
        return new Uint8Array(await crypto.subtle.encrypt(subtleAlgorithm(alg), key, cek));
    }
    if (key.usages.includes('wrapKey')) {
        const cryptoKeyCek = await crypto.subtle.importKey('raw', cek, ...bogusWebCrypto);
        return new Uint8Array(await crypto.subtle.wrapKey('raw', cryptoKeyCek, key, subtleAlgorithm(alg)));
    }
    throw new TypeError('RSA-OAEP key "usages" must include "encrypt" or "wrapKey" for this operation');
};
const decrypt = async (alg, key, encryptedKey) => {
    if (!crypto.isCryptoKey(key)) {
        throw new TypeError(invalidKeyInput(key, 'CryptoKey'));
    }
    checkEncCryptoKey(key, alg, 'decrypt', 'unwrapKey');
    checkKeyLength(alg, key);
    if (key.usages.includes('decrypt')) {
        return new Uint8Array(await crypto.subtle.decrypt(subtleAlgorithm(alg), key, encryptedKey));
    }
    if (key.usages.includes('unwrapKey')) {
        const cryptoKeyCek = await crypto.subtle.unwrapKey('raw', encryptedKey, key, subtleAlgorithm(alg), ...bogusWebCrypto);
        return new Uint8Array(await crypto.subtle.exportKey('raw', cryptoKeyCek));
    }
    throw new TypeError('RSA-OAEP key "usages" must include "decrypt" or "unwrapKey" for this operation');
};

module.exports = {
    encrypt,
    decrypt
}