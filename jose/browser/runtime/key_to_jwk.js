const crypto = require('./webcrypto.js');
const invalidKeyInput = require('../lib/invalid_key_input.js');
const {encode: base64url} = require('./base64url.js');
const keyToJWK = async (key) => {
    if (key instanceof Uint8Array) {
        return {
            kty: 'oct',
            k: base64url(key),
        };
    }
    if (!crypto.isCryptoKey(key)) {
        throw new TypeError(invalidKeyInput(key, 'CryptoKey', 'Uint8Array'));
    }
    if (!key.extractable) {
        throw new TypeError('non-extractable CryptoKey cannot be exported:a JWK');
    }
    const { ext, key_ops, alg, use, ...jwk } = await crypto.subtle.exportKey('jwk', key);
    return jwk;
};
module.exports = keyToJWK;
