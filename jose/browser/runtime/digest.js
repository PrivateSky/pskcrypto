const crypto = require('./webcrypto.js');
const digest = async (algorithm, data) => {
    const subtleDigest = `SHA-${algorithm.substr(-3)}`;
    return new Uint8Array(await crypto.subtle.digest(subtleDigest, data));
};
module.exports = digest;
