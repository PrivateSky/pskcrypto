'use strict';

const crypto = require('crypto');
const config = require('../config');

function computeKMAC(key, data, options) {
    if (key.length !== options.macKeySize) {
        throw new Error('Invalid length of input MAC key')
    }
    return crypto.createHmac(options.hashFunctionName, key).update(data).digest();
}

function verifyKMAC(tag, key, data, options) {
    if (key.length !== options.macKeySize) {
        throw new Error('Invalid length of input MAC key')
    }
    const timingSafeEqual = require('./index').timingSafeEqual;
    const computedTag = computeKMAC(key, data, options)
    return timingSafeEqual(computedTag, tag)
}

module.exports = {
    computeKMAC,
    verifyKMAC
}
