const {compactDecrypt} = require('../jwe/compact/decrypt.js');
const jwtPayload = require('../lib/jwt_claims_set.js');
const {JWTClaimValidationFailed} = require('../util/errors.js');
module.exports.jwtDecrypt = async function jwtDecrypt(jwt, key, options) {
    const decrypted = await compactDecrypt(jwt, key, options);
    const payload = jwtPayload(decrypted.protectedHeader, decrypted.plaintext, options);
    const {protectedHeader} = decrypted;
    if (protectedHeader.iss !== undefined && protectedHeader.iss !== payload.iss) {
        throw new JWTClaimValidationFailed('replicated "iss" claim header parameter mismatch', 'iss', 'mismatch');
    }
    if (protectedHeader.sub !== undefined && protectedHeader.sub !== payload.sub) {
        throw new JWTClaimValidationFailed('replicated "sub" claim header parameter mismatch', 'sub', 'mismatch');
    }
    if (protectedHeader.aud !== undefined &&
        JSON.stringify(protectedHeader.aud) !== JSON.stringify(payload.aud)) {
        throw new JWTClaimValidationFailed('replicated "aud" claim header parameter mismatch', 'aud', 'mismatch');
    }
    const result = {payload, protectedHeader};
    if (typeof key === 'function') {
        return {...result, key: decrypted.key};
    }
    return result;
}
