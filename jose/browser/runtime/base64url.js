const encodeBase64 = (input) => {
    return $$.Buffer.from(input).toString("base64");
};
const encode = (input) => {
    return encodeBase64(input).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
};
const decodeBase64 = (encoded) => {
    return $$.Buffer.from(encoded, "base64").toString();
};
const decode = (input) => {
    let encoded = input;
    if ($$.Buffer.isBuffer(encoded)) {
        encoded = encoded.toString();
    }
    encoded = encoded.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
    try {
        return decodeBase64(encoded);
    }
    catch (_a) {
        throw new TypeError('The input to be decoded is not correctly encoded.');
    }
};

module.exports = {
    encodeBase64,
    encode,
    decodeBase64,
    decode
}