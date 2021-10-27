const subtleAlgorithm = require('./subtle_dsa.js');
const crypto = require('./webcrypto.js');
const checkKeyLength = require('./check_key_length.js');
const getVerifyKey = require('./get_sign_verify_key.js');
const verify = async (alg, key, signature, data) => {
    const cryptoKey = await getVerifyKey(alg, key, 'verify');
    checkKeyLength(alg, cryptoKey);
    const algorithm = subtleAlgorithm(alg, cryptoKey.algorithm.namedCurve);
    try {
        return await crypto.subtle.verify(algorithm, cryptoKey, signature, data);
    }
    catch (_a) {
        return false;
    }
};
module.exports = verify;
