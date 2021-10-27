const {CompactSign} = require('../jws/compact/sign.js');
const {JWTInvalid} = require('../util/errors.js');
const {encoder} = require('../lib/buffer_utils.js');
const {ProduceJWT} = require('./produce.js');

class SignJWT extends ProduceJWT {
    setProtectedHeader(protectedHeader) {
        this._protectedHeader = protectedHeader;
        return this;
    }

    async sign(key, options) {
        var _a;
        const sig = new CompactSign($$.Buffer.from(JSON.stringify(this._payload)));
        sig.setProtectedHeader(this._protectedHeader);
        if (Array.isArray((_a = this._protectedHeader) === null || _a === void 0 ? void 0 : _a.crit) &&
            this._protectedHeader.crit.includes('b64') &&
            this._protectedHeader.b64 === false) {
            throw new JWTInvalid('JWTs MUST NOT use unencoded payload');
        }
        return sig.sign(key, options);
    }
}

module.exports.SignJWT = SignJWT;