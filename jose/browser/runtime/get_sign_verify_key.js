const crypto = require('./webcrypto.js');
const {checkSigCryptoKey} = require('../lib/crypto_key.js');
const invalidKeyInput = require('../lib/invalid_key_input.js');
module.exports = function getCryptoKey(alg, key, usage) {
    if (crypto.isCryptoKey(key)) {
        checkSigCryptoKey(key, alg, usage);
        return key;
    }
    if (key instanceof Uint8Array) {
        if (!alg.startsWith('HS')) {
            throw new TypeError(invalidKeyInput(key, 'CryptoKey'));
        }
        return crypto.subtle.importKey('raw', key, {hash: `SHA-${alg.substr(-3)}`, name: 'HMAC'}, false, [usage]);
    }
    throw new TypeError(invalidKeyInput(key, 'CryptoKey', 'Uint8Array'));
}
