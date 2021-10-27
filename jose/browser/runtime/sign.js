const subtleAlgorithm = require('./subtle_dsa.js');
const crypto = require('./webcrypto.js');
const checkKeyLength = require('./check_key_length.js');
const getSignKey = require('./get_sign_verify_key.js');
const sign = async (alg, key, data) => {
    const cryptoKey = await getSignKey(alg, key, 'sign');
    checkKeyLength(alg, cryptoKey);
    const signature = await crypto.subtle.sign(subtleAlgorithm(alg, cryptoKey.algorithm.namedCurve), cryptoKey, data);
    return new Uint8Array(signature);
};
module.exports = sign;
