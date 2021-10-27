const {JWEInvalid} = require('../util/errors.js');
const {bitLength} = require('./iv.js');
const checkIvLength = (enc, iv) => {
    if (iv.length << 3 !== bitLength(enc)) {
        throw new JWEInvalid('Invalid Initialization Vector length');
    }
};
module.exports = checkIvLength;
