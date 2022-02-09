const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE_MAP = {};
for (let i = 0; i < ALPHABET.length; i++) {
    BASE_MAP[ALPHABET[i]] = i;
}

function encode(source) {
    if (typeof source !== "string") {
        source = source.toString();
    }
    let digits = [];
    let length = 0;
    let b64 = '';
    for (let i = 0; i <= source.length; i += 3) {
        let number = 0;
        let j;
        for (j = i; j < i + 3 && j < source.length; j++) {
            number = number * 256 + source.charCodeAt(j);
        }

        if (j % 3 === 1) {
            number *= 16;
        } else if (j % 3 === 2) {
            number *= 4;
        }

        let previousLength = length;
        while (number > 0) {
            digits[length] = number % 64;
            length++;
            number = Math.floor(number / 64);
        }
        for (let k = previousLength; k < length; k++) {
            b64 += ALPHABET[digits[length + previousLength - 1 - k]];
        }
    }
    let paddingLength = 0;
    if (length % 4 > 0) {
        paddingLength = 4 - length % 4;
    }
    for (let i = 0; i < paddingLength; i++) {
        b64 += "=";
    }
    return b64;
}

function decode(source) {
    if (typeof source !== "string") {
        source = source.toString();
    }
    let paddingLength = 0;
    for (let i = 0; i < source.length; i++) {
        if (source.charAt(i) === "=") {
            paddingLength++;
        }
    }
    let digits = [];
    let length = 0;
    let rest = (source.length - paddingLength) % 4;
    let size = (source.length - paddingLength - rest) * 3 / 4;
    if (paddingLength === 2) {
        size++;
    } else if (paddingLength === 1) {
        size += 2;
    }

    let b256 = '';
    for (let i = 0; i <= source.length - paddingLength; i += 4) {
        let number = 0;
        let j;
        for (j = i; j < i + 4 && j < source.length - paddingLength - 1; j++) {
            number = number * 64 + BASE_MAP[source.charAt(j)];
        }

        if (j % 4 === 1) {
            number = number * 4 + Math.floor(BASE_MAP[source.charAt(j)] / 16);
        } else if (j % 4 === 2) {
            number = number * 16 + Math.floor(BASE_MAP[source.charAt(j)] / 4);
        } else if (j % 4 === 3) {
            number = number * 64 + BASE_MAP[source.charAt(j)];
        }

        let previousLength = length;
        while (length - previousLength < 3 && length < size) {
            digits[length] = number % 256;
            length++;
            number = Math.floor(number / 256);
        }
        for (let k = previousLength; k < length; k++) {
            b256 += String.fromCharCode(digits[length + previousLength - 1 - k]);
        }
    }

    return Buffer.from(b256);
}

function encodeBase64(data) {
    if (!Buffer.isBuffer(data)) {
        data = Buffer.from(data);
    }

    return data.toString("base64");
}

function decodeBase64(data) {
    if (!Buffer.isBuffer(data)) {
        data = Buffer.from(data);
    }

    return Buffer.from(data.toString(), "base64");
}

module.exports = {
    encode: encodeBase64,
    decode: decodeBase64
}