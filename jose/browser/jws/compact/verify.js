const {flattenedVerify} = require('../flattened/verify.js');
const {JWSInvalid} = require('../../util/errors.js');
const {decoder} = require('../../lib/buffer_utils.js');
module.exports.compactVerify =  async function compactVerify(jws, key, options) {
    if (jws instanceof Uint8Array) {
        jws = jws.toString();
    }
    if (typeof jws !== 'string') {
        throw new JWSInvalid('Compact JWS must be a string or Uint8Array');
    }
    const { 0: protectedHeader, 1: payload, 2: signature, length } = jws.split('.');
    if (length !== 3) {
        throw new JWSInvalid('Invalid Compact JWS');
    }
    const verified = await flattenedVerify({
        payload: (payload || undefined),
        protected: protectedHeader || undefined,
        signature: (signature || undefined),
    }, key, options);
    const result = { payload: verified.payload, protectedHeader: verified.protectedHeader };
    if (typeof key === 'function') {
        return { ...result, key: verified.key };
    }
    return result;
}
