const {JOSENotSupported} = require('../util/errors.js');
const crypto = require("crypto");
module.exports.bitLength = function bitLength(alg) {
    switch (alg) {
        case 'A128CBC-HS256':
            return 128;
        case 'A128GCM':
            return 96;
        case 'A128GCMKW':
            return 96;
        case 'A192CBC-HS384':
            return 128;
        case 'A192GCM':
            return 96;
        case 'A192GCMKW':
            return 96;
        case 'A256CBC-HS512':
            return 128;
        case 'A256GCM':
            return 96;
        case 'A256GCMKW':
            return 96;
        default:
            throw new JOSENotSupported(`Unsupported JWE Algorithm: ${alg}`);
    }
}
module.exports = (alg) => crypto.randomBytes(module.exports.bitLength(alg) >> 3);
