const {decode: base64url} = require('./base64url.js');
const {decoder} = require('../lib/buffer_utils.js');
const isObject = require('../lib/is_object.js');
module.exports.decodeProtectedHeader = function decodeProtectedHeader(token) {
    let protectedB64u;
    if (typeof token === 'string') {
        const parts = token.split('.');
        if (parts.length === 3 || parts.length === 5) {
            ;
            [protectedB64u] = parts;
        }
    } else if (typeof token === 'object' && token) {
        if ('protected' in token) {
            protectedB64u = token.protected;
        } else {
            throw new TypeError('Token does not contain a Protected Header');
        }
    }
    try {
        if (typeof protectedB64u !== 'string' || !protectedB64u) {
            throw new Error();
        }
        const result = JSON.parse(base64url(protectedB64u).toString());
        if (!isObject(result)) {
            throw new Error();
        }
        return result;
    } catch (_a) {
        throw new TypeError('Invalid Token or Protected Header formatting');
    }
}
