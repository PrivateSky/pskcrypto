'use strict';

const cipher = require('./cipher')
const kdf = require('./kdf')
const kmac = require('./kmac')
const sig = require('./digitalsig')
const crypto = require('crypto')

module.exports = {
    timingSafeEqual: crypto.timingSafeEqual,
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
