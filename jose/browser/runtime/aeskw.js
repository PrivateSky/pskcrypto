const bogusWebCrypto = require('./bogus.js');
const crypto = require('./webcrypto.js');
const {checkEncCryptoKey} = require('../lib/crypto_key.js');
const invalidKeyInput = require('../lib/invalid_key_input.js');

function checkKeySize(key, alg) {
    if (key.algorithm.length !== parseInt(alg.substr(1, 3), 10)) {
        throw new TypeError(`Invalid key size for alg: ${alg}`);
    }
}

function getCryptoKey(key, alg, usage) {
    if (crypto.isCryptoKey(key)) {
        checkEncCryptoKey(key, alg, usage);
        return key;
    }
    if (key instanceof Uint8Array) {
        return crypto.subtle.importKey('raw', key, 'AES-KW', true, [usage]);
    }
    throw new TypeError(invalidKeyInput(key, 'CryptoKey', 'Uint8Array'));
}

const wrap = async (alg, key, cek) => {
    const cryptoKey = await getCryptoKey(key, alg, 'wrapKey');
    checkKeySize(cryptoKey, alg);
    const cryptoKeyCek = await crypto.subtle.importKey('raw', cek, ...bogusWebCrypto);
    return new Uint8Array(await crypto.subtle.wrapKey('raw', cryptoKeyCek, cryptoKey, 'AES-KW'));
};
const unwrap = async (alg, key, encryptedKey) => {
    const cryptoKey = await getCryptoKey(key, alg, 'unwrapKey');
    checkKeySize(cryptoKey, alg);
    const cryptoKeyCek = await crypto.subtle.unwrapKey('raw', encryptedKey, cryptoKey, 'AES-KW', ...bogusWebCrypto);
    return new Uint8Array(await crypto.subtle.exportKey('raw', cryptoKeyCek));
};

module.exports = {
    wrap,
    unwrap
}