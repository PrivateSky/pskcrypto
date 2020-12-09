const asn1 = require('../asn1/asn1');
const BN = require('../asn1/bignum/bn');

const EcdsaDerSig = asn1.define('ECPrivateKey', function() {
    return this.seq().obj(
        this.key('r').int(),
        this.key('s').int()
    );
});

/// helper functions for ethereum signature encoding
function bnToBuffer(bn) {
    return stripZeros($$.Buffer.from(padToEven(bn.toString(16)), 'hex'));
}

function padToEven(str) {
    return str.length % 2 ? '0' + str : str;
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
///

function decodeDERIntoASN1ETH(derSignatureBuffer){
    const rsSig = EcdsaDerSig.decode(derSignatureBuffer, 'der');
    const signArray = [bnToBuffer(rsSig.r),bnToBuffer(rsSig.s)];
    //build signature
    return '0x'+$$.Buffer.concat(signArray).toString('hex');
}

function asn1SigSigToConcatSig(asn1SigBuffer) {
    const rsSig = EcdsaDerSig.decode(asn1SigBuffer, 'der');
    return $$.Buffer.concat([
        rsSig.r.toArrayLike($$.Buffer, 'be', 32),
        rsSig.s.toArrayLike($$.Buffer, 'be', 32)
    ]);
}

function concatSigToAsn1SigSig(concatSigBuffer) {
    const r = new BN(concatSigBuffer.slice(0, 32).toString('hex'), 16, 'be');
    const s = new BN(concatSigBuffer.slice(32).toString('hex'), 16, 'be');
    return EcdsaDerSig.encode({r, s}, 'der');
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
    decodeDERIntoASN1ETH
};