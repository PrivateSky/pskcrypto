const digest = require('../runtime/digest.js');
const {encode: base64url} = require('../runtime/base64url.js');
const {JOSENotSupported, JWKInvalid} = require('../util/errors.js');
const {encoder} = require('../lib/buffer_utils.js');
const isObject = require('../lib/is_object.js');
const check = (value, description) => {
    if (typeof value !== 'string' || !value) {
        throw new JWKInvalid(`${description} missing or invalid`);
    }
};
module.exports.calculateJwkThumbprint = async function calculateJwkThumbprint(jwk, digestAlgorithm = 'sha256') {
    if (!isObject(jwk)) {
        throw new TypeError('JWK must be an object');
    }
    let components;
    switch (jwk.kty) {
        case 'EC':
            check(jwk.crv, '"crv" (Curve) Parameter');
            check(jwk.x, '"x" (X Coordinate) Parameter');
            check(jwk.y, '"y" (Y Coordinate) Parameter');
            components = {crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y};
            break;
        case 'OKP':
            check(jwk.crv, '"crv" (Subtype of Key Pair) Parameter');
            check(jwk.x, '"x" (Public Key) Parameter');
            components = {crv: jwk.crv, kty: jwk.kty, x: jwk.x};
            break;
        case 'RSA':
            check(jwk.e, '"e" (Exponent) Parameter');
            check(jwk.n, '"n" (Modulus) Parameter');
            components = {e: jwk.e, kty: jwk.kty, n: jwk.n};
            break;
        case 'oct':
            check(jwk.k, '"k" (Key Value) Parameter');
            components = {k: jwk.k, kty: jwk.kty};
            break;
        default:
            throw new JOSENotSupported('"kty" (Key Type) Parameter missing or unsupported');
    }
    const data = $$.Buffer.from(JSON.stringify(components));
    return base64url(await digest(digestAlgorithm, data));
}
