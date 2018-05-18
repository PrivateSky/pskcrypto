const crypto = require('crypto');
var ecdsa = require('./ecdsa/lib/ECDSA').createECDSA();

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
    var cipher = crypto.createCipheriv('aes-256-ctr', key,iv);
    var crypted = Buffer.from(cipher.update(buf,'binary'), 'binary');
    var final = Buffer.from(cipher.final('binary'),'binary');
    crypted = Buffer.concat([crypted, final]);
    return Buffer.concat([iv, crypted]);
};


exports.decryptJson = function(encryptedData, key){

    var cipher = encryptedData.slice(16);
    var iv = encryptedData.slice(0,16);
    var decipher = crypto.createDecipheriv('aes-256-ctr', key, iv);
    var dec = Buffer.from(decipher.update(cipher,'hex','binary'), 'binary');
    var final = Buffer.from(decipher.final('binary'), 'binary');
    dec = Buffer.concat([dec, final]);

    return JSON.parse(dec.toString());
};

exports.encryptBlob = function (data, key) {
    var iv = crypto.randomBytes(16);
    var cipher = crypto.createCipheriv('aes-256-ctr', key,iv);
    var crypted = Buffer.from(cipher.update(data),'binary');
    var final = Buffer.from(cipher.final('binary'),'binary');
    crypted = Buffer.concat([crypted, final]);

    return Buffer.concat([iv, crypted]);
};

exports.decryptBlob = function (encryptedData, key) {
    var cipher = encryptedData.slice(16);
    var iv = encryptedData.slice(0,16);
    var decipher = crypto.createDecipheriv('aes-256-ctr', key, iv);
    var dec = Buffer.from(decipher.update(cipher,'hex','binary'), 'binary');
    var final = Buffer.from(decipher.final('binary'), 'binary');

    return Buffer.concat([dec, final]);
};



exports.generateEncryptionKey = function(){
    return crypto.randomBytes(32);
};


