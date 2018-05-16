const crypto = require('crypto');
const KeyEncoder = require('./keyEncoder');



function ECDSA(curveName){
    this.curve = curveName || 'secp256k1';
    var self = this;

    this.generateKeyPair = function() {
        var result = {};
        var ec = crypto.createECDH(self.curve);
        result.public = ec.generateKeys('hex');
        result.private = ec.getPrivateKey('hex');
        return keysToPEM(result);
    }

    function keysToPEM(keys){
        var result = {};
        var ECPrivateKeyASN = KeyEncoder.ECPrivateKeyASN;
        var SubjectPublicKeyInfoASN = KeyEncoder.SubjectPublicKeyInfoASN;
        var keyEncoder = new KeyEncoder(self.curve);

        var privateKeyObject = keyEncoder.privateKeyObject(keys.private,keys.public);
        var publicKeyObject = keyEncoder.publicKeyObject(keys.public);

        result.private = ECPrivateKeyASN.encode(privateKeyObject, 'pem', privateKeyObject.pemOptions);
        result.public = SubjectPublicKeyInfoASN.encode(publicKeyObject, 'pem', publicKeyObject.pemOptions);
        return result;

    }

    this.sign = function (privateKey,digest) {
        var sign = crypto.createSign("sha256");

        sign.update(digest);

        var signature = sign.sign(privateKey,'hex');

        return signature;
    }

    this.verify = function (publicKey,signature,digest) {

        var verify = crypto.createVerify('sha256');

        verify.update(digest);

        return verify.verify(publicKey,signature,'hex');
    }

}



exports.createECDSA = function (curve){
    return new ECDSA(curve);
}




