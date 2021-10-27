const {encode: base64url} = require('../../runtime/base64url.js');
const sign = require('../../runtime/sign.js');
const isDisjoint = require('../../lib/is_disjoint.js');
const {JWSInvalid} = require('../../util/errors.js');
const {encoder, decoder, concat} = require('../../lib/buffer_utils.js');
const checkKeyType = require('../../lib/check_key_type.js');
const validateCrit = require('../../lib/validate_crit.js');
class FlattenedSign {
    constructor(payload) {
        if (!(payload instanceof Uint8Array)) {
            throw new TypeError('payload must be an instance of Uint8Array');
        }
        this._payload = payload;
    }
    setProtectedHeader(protectedHeader) {
        if (this._protectedHeader) {
            throw new TypeError('setProtectedHeader can only be called once');
        }
        this._protectedHeader = protectedHeader;
        return this;
    }
    setUnprotectedHeader(unprotectedHeader) {
        if (this._unprotectedHeader) {
            throw new TypeError('setUnprotectedHeader can only be called once');
        }
        this._unprotectedHeader = unprotectedHeader;
        return this;
    }
    async sign(key, options) {
        if (!this._protectedHeader && !this._unprotectedHeader) {
            throw new JWSInvalid('either setProtectedHeader or setUnprotectedHeader must be called before #sign()');
        }
        if (!isDisjoint(this._protectedHeader, this._unprotectedHeader)) {
            throw new JWSInvalid('JWS Protected and JWS Unprotected Header Parameter names must be disjoint');
        }
        const joseHeader = {
            ...this._protectedHeader,
            ...this._unprotectedHeader,
        };
        const extensions = validateCrit(JWSInvalid, new Map([['b64', true]]), options === null || options === void 0 ? void 0 : options.crit, this._protectedHeader, joseHeader);
        let b64 = true;
        if (extensions.has('b64')) {
            b64 = this._protectedHeader.b64;
            if (typeof b64 !== 'boolean') {
                throw new JWSInvalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
            }
        }
        const { alg } = joseHeader;
        if (typeof alg !== 'string' || !alg) {
            throw new JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
        }
        checkKeyType(alg, key, 'sign');
        let payload = this._payload;
        if (b64) {
            payload = $$.Buffer.from(base64url(payload));
        }
        let protectedHeader;
        if (this._protectedHeader) {
            protectedHeader = $$.Buffer.from(base64url(JSON.stringify(this._protectedHeader)));
        }
        else {
            protectedHeader = $$.Buffer.from('');
        }
        const data = concat(protectedHeader, $$.Buffer.from('.'), payload);
        const signature = await sign(alg, key, data);
        const jws = {
            signature: base64url(signature),
            payload: '',
        };
        if (b64) {
            jws.payload = payload.toString();
        }
        if (this._unprotectedHeader) {
            jws.header = this._unprotectedHeader;
        }
        if (this._protectedHeader) {
            jws.protected = protectedHeader.toString();
        }
        return jws;
    }
}

module.exports.FlattenedSign = FlattenedSign;