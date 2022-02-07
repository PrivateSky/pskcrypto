const keyEncoder = require("../keyEncoder");
const BN = require('../asn1/bignum/bn');
const ECKeyGenerator = require("../ECKeyGenerator");
const utils = require("../utils/cryptoUtils");
/// helper functions for ethereum signature encoding
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
    r = new BN(r.toString('hex'), 16, 'be');
    s = new BN(s.toString('hex'), 16, 'be');
    return {r, s}
}

function generateV(privateKey) {
    const keyPairGenerator = ECKeyGenerator.createECKeyGenerator();
    const rawPublicKey = keyPairGenerator.getPublicKey(privateKey);

    // const x = new BN(rawPublicKey.slice(1, 33).toString("hex"), 16);
    const y = new BN(rawPublicKey.slice(33).toString("hex"), 16);
    let v = 0x00;
    if (y.isEven()) {
        v = 0x00;
    }

    v = 0x1b + v;
    return $$.Buffer.from(v.toString(16), "hex");
}

function convertRSVSignatureToDer(rsvSignature) {
    const r = new BN(rsvSignature.slice(0, 32).toString("hex"), 16);
    const s = new BN(rsvSignature.slice(32, 64).toString("hex"), 16);
    const derEncodedSignature = keyEncoder.ECDSASignature.encode({r,s}, "der");
    return derEncodedSignature;
}

function sign(data, privateKey) {
    const keyPairGenerator = ECKeyGenerator.createECKeyGenerator();
    const pemPrivateKey = keyPairGenerator.convertPrivateKey(privateKey);
    const pskcrypto = require("../PskCrypto");
    const signature = pskcrypto.sign("sha256", data, pemPrivateKey);
    console.log(signature.toString("hex"));
    const {r, s} = getRSFromSignature(signature);
    const v = generateV(privateKey);
    return $$.Buffer.concat([r.toArrayLike($$.Buffer), s.toArrayLike($$.Buffer), v]);
}

function verify(data, signature, publicKey) {
    const keyPairGenerator = ECKeyGenerator.createECKeyGenerator();
    const pskcrypto = require("../PskCrypto");
    if (!$$.Buffer.isBuffer(data)) {
        data = $$.Buffer.from(data);
    }
    const derSignature = convertRSVSignatureToDer(signature);
    const pemPublicKey = keyPairGenerator.convertPublicKey(publicKey);
    return pskcrypto.verify("sha256", data, pemPublicKey, derSignature);
}

function asn1SigSigToConcatSig(asn1SigBuffer) {
    const rsSig = keyEncoder.ECDSASignature.decode(asn1SigBuffer, 'der');
    return $$.Buffer.concat([
        rsSig.r.toArrayLike($$.Buffer, 'be', 32),
        rsSig.s.toArrayLike($$.Buffer, 'be', 32)
    ]);
}

function concatSigToAsn1SigSig(concatSigBuffer) {
    const r = new BN(concatSigBuffer.slice(0, 32).toString('hex'), 16, 'be');
    const s = new BN(concatSigBuffer.slice(32).toString('hex'), 16, 'be');
    return keyEncoder.ECDSASignature.encode({r, s}, 'der');
}

function ecdsaSign(data, key) {
    if (typeof data === "string") {
        data = $$.Buffer.from(data);
    }
    const crypto = require('crypto');
    const sign = crypto.createSign('sha256');
    sign.update(data);
    const asn1SigBuffer = sign.sign(key, 'buffer');
    return asn1SigSigToConcatSig(asn1SigBuffer);
}

/**
 * @return {string}
 */
function EthRSSign(data, key) {
    if (typeof data === "string") {
        data = $$.Buffer.from(data);
    }
    //by default it will create DER encoded signature
    const crypto = require('crypto');
    const sign = crypto.createSign('sha256');
    sign.update(data);
    const derSignatureBuffer = sign.sign(key, 'buffer');
    return decodeDERIntoASN1ETH(derSignatureBuffer);
}

function ecdsaVerify(data, signature, key) {
    const crypto = require('crypto');
    const verify = crypto.createVerify('SHA256');
    verify.update(data);
    const asn1sig = concatSigToAsn1SigSig(signature);
    return verify.verify(key, new $$.Buffer(asn1sig, 'hex'));
}

module.exports = {
    decodeDERIntoASN1ETH,
    sign,
    verify
};