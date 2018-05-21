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


exports.encryptJson = function(data, key){
    var iv = crypto.randomBytes(16);
    var buf = Buffer.from(JSON.stringify(data), 'binary');
    var cipher = crypto.createCipheriv(algorithm, key, iv);

    var encrypted = Buffer.from(cipher.update(buf,'binary'), 'binary');
    var final = Buffer.from(cipher.final('binary'),'binary');
    encrypted = Buffer.concat([encrypted, final]);
    var tag = cipher.getAuthTag();
    return {
        iv: iv,
        content: encrypted,
        tag: tag
    }
};


exports.decryptJson = function(encryptedData, key){

    var ciphertext = encryptedData.content;
    var iv = encryptedData.iv;
    var decipher = crypto.createDecipheriv(algorithm, key, iv);
    decipher.setAuthTag(encryptedData.tag);
    var dec = Buffer.from(decipher.update(ciphertext,'hex','binary'), 'binary');
    var final = Buffer.from(decipher.final('binary'), 'binary');
    dec = Buffer.concat([dec, final]);

    return JSON.parse(dec.toString());
};

exports.encryptBlob = function (data, key) {
    var iv = crypto.randomBytes(16);
    var cipher = crypto.createCipheriv(algorithm, key,iv);
    var encrypted = Buffer.from(cipher.update(data),'binary');
    var final = Buffer.from(cipher.final('binary'),'binary');
    encrypted = Buffer.concat([encrypted, final]);

    var tag = cipher.getAuthTag();
    return {
        iv: iv,
        content: encrypted,
        tag: tag
    }
};

exports.decryptBlob = function (encryptedData, key) {
    var ciphertext = encryptedData.content;
    var iv = encryptedData.iv;
    var decipher = crypto.createDecipheriv(algorithm, key, iv);
    decipher.setAuthTag(encryptedData.tag);
    var dec = Buffer.from(decipher.update(ciphertext,'hex','binary'), 'binary');
    var final = Buffer.from(decipher.final('binary'), 'binary');

    return Buffer.concat([dec, final]);
};



exports.generateEncryptionKey = function(){
    return crypto.randomBytes(32);
};


