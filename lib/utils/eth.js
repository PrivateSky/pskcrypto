const keyEncoder = require("../keyEncoder");
const BN = require('../asn1/bignum/bn');
const ECKeyGenerator = require("../ECKeyGenerator");
const utils = require("../utils/cryptoUtils");

function bnToBuffer(bn) {
    return stripZeros($$.Buffer.from(padToEven(bn.toString(16)), 'hex'));
}

function padToEven(str) {
    return str.length % 2 ? '0' + str : str;
}

function padToLength(buff, len) {
    const buffer = Buffer.alloc(len);

    buffer.fill(0);
    const offset = len - buff.length;
    for (let i = 0; i < len - offset; i++) {
        buffer[i + offset] = buff[i]
    }
    return buffer;
}

function stripZeros(buffer) {
    var i = 0; // eslint-disable-line
    for (i = 0; i < buffer.length; i++) {
        if (buffer[i] !== 0) {
            break;
        }
    }
    return i > 0 ? buffer.slice(i) : buffer;
}

function decodeDERIntoASN1ETH(derSignatureBuffer) {
    const rsSig = keyEncoder.ECDSASignature.decode(derSignatureBuffer, 'der');
    let rBuffer = padToLength(bnToBuffer(rsSig.r), 32);
    let sBuffer = padToLength(bnToBuffer(rsSig.s), 32);
    //build signature
    return '0x' + $$.Buffer.concat([rBuffer, sBuffer]).toString('hex');
}

function getRSFromSignature(signature) {
    const rsSig = keyEncoder.ECDSASignature.decode(signature, 'der');
    let r = padToLength(bnToBuffer(rsSig.r), 32);
    let s = padToLength(bnToBuffer(rsSig.s), 32);
    return {r, s}
}

function convertRSSignatureToDer(rsvSignature) {
    const r = new BN(rsvSignature.slice(0, 32).toString("hex"), 16);
    const s = new BN(rsvSignature.slice(32).toString("hex"), 16);
    const derEncodedSignature = keyEncoder.ECDSASignature.encode({r, s}, "der");
    return derEncodedSignature;
}

function sign(data, privateKey) {
    const keyPairGenerator = ECKeyGenerator.createECKeyGenerator();
    const pemPrivateKey = keyPairGenerator.convertPrivateKey(privateKey);
    const pskcrypto = require("../PskCrypto");
    const signature = pskcrypto.sign("sha256", data, pemPrivateKey);
    const {r, s} = getRSFromSignature(signature);
    return $$.Buffer.concat([r, s]);
}

function verify(data, signature, publicKey) {
    if (!$$.Buffer.isBuffer(data)) {
        data = $$.Buffer.from(data);
    }

    const keyPairGenerator = ECKeyGenerator.createECKeyGenerator();
    const pskcrypto = require("../PskCrypto");

    const derSignature = convertRSSignatureToDer(signature);
    let pemPublicKey;
    if (utils.isPemEncoded(publicKey)) {
        pemPublicKey = publicKey;
    } else {
        pemPublicKey = keyPairGenerator.convertPublicKey(publicKey);
    }
    return pskcrypto.verify("sha256", data, pemPublicKey, derSignature);
}

module.exports = {
    decodeDERIntoASN1ETH,
    sign,
    verify
};
