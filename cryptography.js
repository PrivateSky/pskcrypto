const crypto = require('crypto');
var ecdsa = require('./ecdsa/lib/ECDSA').createECDSA();

exports.generateECDSAKeyPair = function(){
    return ecdsa.generateKeyPair();
};


exports.sign = function(privateKey, digest){
    return ecdsa.sign(privateKey,digest);
};

exports.verify = function(publicKey, digest){
    return ecdsa.verify(publicKey, digest);
}

exports.encrypt = function(plaintext, key, iv){

    var cipher = crypto.createCipheriv('aes-256-ctr', key,iv);
    var crypted = cipher.update(plaintext,'utf8','hex');
    crypted += cipher.final('hex');
    return crypted;
};

exports.decrypt = function(text, key, iv){
    var decipher = crypto.createDecipheriv('aes-256-ctr', key,iv);
    var dec = decipher.update(text,'hex','utf8')
    dec += decipher.final('utf8');
    return dec;
};

exports.generateEncryptionKey = function(){
    return crypto.randomBytes(32);
};

exports.generateIV = function(){
    return crypto.randomBytes(16);
};
