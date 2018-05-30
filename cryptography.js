const crypto = require('crypto');
var ecdsa = require('./ecdsa/lib/ECDSA').createECDSA();
var algorithm = 'aes-256-gcm';

exports.generateECDSAKeyPair = function(){
    return ecdsa.generateKeyPair();
};


exports.sign = function(privateKey, digest){
    return ecdsa.sign(privateKey,digest);
};

exports.verify = function(publicKey, signature, digest){
    return ecdsa.verify(publicKey, signature, digest);
}


exports.encryptJson = function(data, key, aad){
    var iv = crypto.randomBytes(16);
    var buf = Buffer.from(JSON.stringify(data), 'binary');
    var cipher = crypto.createCipheriv(algorithm, key, iv);
    cipher.setAAD(aad);
    var encrypted = Buffer.from(cipher.update(buf,'binary'), 'binary');
    var final = Buffer.from(cipher.final('binary'),'binary');
    encrypted = Buffer.concat([encrypted, final]);
    var tag = cipher.getAuthTag();
    var cipherText = {
        iv: iv,
        content: encrypted,
        tag: tag
    };

    return JSON.stringify(cipherText);
};


exports.decryptJson = function(encryptedData, key, aad){
    var cryptoObj = JSON.parse(encryptedData);
    var ciphertext = cryptoObj.content;
    var iv = cryptoObj.iv;
    var decipher = crypto.createDecipheriv(algorithm, key, iv);
    decipher.setAuthTag(cryptoObj.tag);
    decipher.setAAD(aad);
    var dec = Buffer.from(decipher.update(ciphertext,'hex','binary'), 'binary');
    var final = Buffer.from(decipher.final('binary'), 'binary');
    dec = Buffer.concat([dec, final]);

    return JSON.parse(dec.toString());
};

exports.encryptBlob = function (data, key, aad) {
    var iv = crypto.randomBytes(16);
    var cipher = crypto.createCipheriv(algorithm, key,iv);
    cipher.setAAD(aad);
    var encrypted = Buffer.from(cipher.update(data),'binary');
    var final = Buffer.from(cipher.final('binary'),'binary');
    encrypted = Buffer.concat([encrypted, final]);

    var tag = cipher.getAuthTag();
    var cipherText = {
        iv: iv,
        content: encrypted,
        tag: tag
    };

    return JSON.stringify(cipherText);
};

exports.decryptBlob = function (encryptedData, key, aad) {
    var cryptoObj = JSON.parse(encryptedData);
    var ciphertext = cryptoObj.content;
    var iv = cryptoObj.iv;
    var decipher = crypto.createDecipheriv(algorithm, key, iv);
    decipher.setAuthTag(cryptoObj.tag);
    decipher.setAAD(aad);
    var dec = Buffer.from(decipher.update(ciphertext,'hex','binary'), 'binary');
    var final = Buffer.from(decipher.final('binary'), 'binary');

    return Buffer.concat([dec, final]);
};



exports.generateEncryptionKey = function(){
    return crypto.randomBytes(32);
};


