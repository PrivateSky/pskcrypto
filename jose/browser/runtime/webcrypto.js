let globalThis = require('./global.js');
const isNodeJs = globalThis.isNodeJs();
globalThis = isNodeJs ? require("crypto").webcrypto : globalThis;
module.exports = isNodeJs ? globalThis : globalThis.crypto;
module.exports.isCryptoKey = function isCryptoKey(key) {
    if (typeof globalThis.CryptoKey === 'undefined') {
        return false;
    }
    return key != null && key instanceof globalThis.CryptoKey;
}
