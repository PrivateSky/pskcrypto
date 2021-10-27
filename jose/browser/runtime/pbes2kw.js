const {p2s: concatSalt} = require('../lib/buffer_utils.js');
const {encode: base64url} = require('./base64url.js');
const {wrap, unwrap} = require('./aeskw.js');
const checkP2s = require('../lib/check_p2s.js');
const webcrypto = require('./webcrypto.js');
const crypto = require("crypto");
const {checkEncCryptoKey} = require('../lib/crypto_key.js');
const invalidKeyInput = require('../lib/invalid_key_input.js');

function getCryptoKey(key, alg) {
    if (key instanceof Uint8Array) {
        return webcrypto.subtle.importKey('raw', key, 'PBKDF2', false, ['deriveBits']);
    }
    if (webcrypto.isCryptoKey(key)) {
        checkEncCryptoKey(key, alg, 'deriveBits', 'deriveKey');
        return key;
    }
    throw new TypeError(invalidKeyInput(key, 'CryptoKey', 'Uint8Array'));
}

async function deriveKey(p2s, alg, p2c, key) {
    checkP2s(p2s);
    const salt = concatSalt(alg, p2s);
    const keylen = parseInt(alg.substr(13, 3), 10);
    const subtleAlg = {
        hash: `SHA-${alg.substr(8, 3)}`,
        iterations: p2c,
        name: 'PBKDF2',
        salt,
    };
    const wrapAlg = {
        length: keylen,
        name: 'AES-KW',
    };
    const cryptoKey = await getCryptoKey(key, alg);
    if (cryptoKey.usages.includes('deriveBits')) {
        return new Uint8Array(await webcrypto.subtle.deriveBits(subtleAlg, cryptoKey, keylen));
    }
    if (cryptoKey.usages.includes('deriveKey')) {
        return webcrypto.subtle.deriveKey(subtleAlg, cryptoKey, wrapAlg, false, ['wrapKey', 'unwrapKey']);
    }
    throw new TypeError('PBKDF2 key "usages" must include "deriveBits" or "deriveKey"');
}

const encrypt = async (alg, key, cek, p2c = Math.floor(Math.random() * 2049) + 2048, p2s = crypto.randomBytes(16)) => {
    const derived = await deriveKey(p2s, alg, p2c, key);
    const encryptedKey = await wrap(alg.substr(-6), derived, cek);
    return {encryptedKey, p2c, p2s: base64url(p2s)};
};
const decrypt = async (alg, key, encryptedKey, p2c, p2s) => {
    const derived = await deriveKey(p2s, alg, p2c, key);
    return unwrap(alg.substr(-6), derived, encryptedKey);
};

module.exports = {
    encrypt,
    decrypt
}