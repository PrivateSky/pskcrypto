const encrypt = require('../runtime/encrypt.js');
const decrypt = require('../runtime/decrypt.js');
const generateIv = require('./iv.js');
const {encode: base64url} = require('../runtime/base64url.js');
module.exports.wrap = async function wrap(alg, key, cek, iv) {
    const jweAlgorithm = alg.substr(0, 7);
    iv || (iv = generateIv(jweAlgorithm));
    const {ciphertext: encryptedKey, tag} = await encrypt(jweAlgorithm, cek, key, iv, new Uint8Array(0));
    return {encryptedKey, iv: base64url(iv), tag: base64url(tag)};
}
module.exports.unwrap = async function unwrap(alg, key, encryptedKey, iv, tag) {
    const jweAlgorithm = alg.substr(0, 7);
    return decrypt(jweAlgorithm, key, encryptedKey, iv, tag, new Uint8Array(0));
}
