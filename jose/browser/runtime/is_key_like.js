const {isCryptoKey} = require('./webcrypto.js');
module.exports = (key) => {
    return isCryptoKey(key);
};
module.exports.types = ['CryptoKey'];
