'use strict';

const cipher = require('./cipher')
const kdf = require('./kdf')
const kmac = require('./kmac')
const sig = require('./digitalsig')
const crypto = require('crypto')

module.exports = {
    timingSafeEqual: function(a, b){
        const hashA = crypto.createHash("sha256");
        const digestA = hashA.update(a).digest("hex");

        const hashB = crypto.createHash("sha256");
        const digestB = hashB.update(b).digest("hex");
        return digestA === digestB;
    },
    getRandomBytes: crypto.randomBytes,
    computeDigitalSignature: sig.computeDigitalSignature,
    verifyDigitalSignature: sig.verifyDigitalSignature,
    symmetricEncrypt: cipher.symmetricEncrypt,
    symmetricDecrypt: cipher.symmetricDecrypt,
    KMAC: kmac,
    ECEphemeralKeyAgreement: require('./ecephka'),
    KDF: kdf.KDF2,
    PublicKeySerializer: require('./pkserializer'),
    PublicKeyDeserializer: require('./pkdeserializer')
}
