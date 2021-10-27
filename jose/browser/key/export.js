const {toSPKI: exportPublic} = require('../runtime/asn1.js');
const {toPKCS8: exportPrivate} = require('../runtime/asn1.js');
const keyToJWK = require('../runtime/key_to_jwk.js');

module.exports.exportSPKI = function exportSPKI(key) {
    return exportPublic(key);
}

module.exports.exportPKCS8 = function exportPKCS8(key) {
    return exportPrivate(key);
}

module.exports.exportJWK = function exportJWK(key) {
    return keyToJWK(key);
}
