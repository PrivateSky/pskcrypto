const {JWEInvalid} = require('../util/errors.js');
const checkCekLength = (cek, expected) => {
    if (cek.length << 3 !== expected) {
        throw new JWEInvalid('Invalid Content Encryption Key length');
    }
};
module.exports = checkCekLength;
