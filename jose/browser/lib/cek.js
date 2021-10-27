const {JOSENotSupported} = require('../util/errors.js');
const crypto = require("crypto");
module.exports.bitLength = function bitLength(alg) {
    switch (alg) {
        case 'A128CBC-HS256':
            return 256;
        case 'A192CBC-HS384':
            return 384;
        case 'A256CBC-HS512':
            return 512;
        case 'A128GCM':
            return 128;
        case 'A192GCM':
            return 192;
        case 'A256GCM':
            return 256;
        default:
            throw new JOSENotSupported(`Unsupported JWE Algorithm: ${alg}`);
    }
}
module.exports = (alg) => crypto.randomBytes(module.exports.bitLength(alg) >> 3);
