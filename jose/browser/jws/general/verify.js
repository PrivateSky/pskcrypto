const {flattenedVerify} = require('../flattened/verify.js');
const {JWSInvalid, JWSSignatureVerificationFailed} = require('../../util/errors.js');
const isObject = require('../../lib/is_object.js');
module.exports.generalVerify = async function generalVerify(jws, key, options) {
    if (!isObject(jws)) {
        throw new JWSInvalid('General JWS must be an object');
    }
    if (!Array.isArray(jws.signatures) || !jws.signatures.every(isObject)) {
        throw new JWSInvalid('JWS Signatures missing or incorrect type');
    }
    for (const signature of jws.signatures) {
        try {
            return await flattenedVerify({
                header: signature.header,
                payload: jws.payload,
                protected: signature.protected,
                signature: signature.signature,
            }, key, options);
        } catch (_a) {
        }
    }
    throw new JWSSignatureVerificationFailed();
}
