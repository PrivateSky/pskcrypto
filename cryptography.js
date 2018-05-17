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

function bytesToString(bytes){
    var result = "";
    for(var i = 0; i < bytes.length; i++){
        result += (String.fromCharCode(bytes[i]));
    }
    return result;
}

exports.encryptJson = function(data, key){
    var iv = crypto.randomBytes(16);
    var str = JSON.stringify(data);
    var cipher = crypto.createCipheriv('aes-256-ctr', key,iv);
    var crypted = cipher.update(str,'utf8','hex');
    crypted += cipher.final('hex');
    var ivStr = bytesToString(iv);
    return ivStr + crypted;
};


exports.decryptJson = function(ciphertext, key){

    var ivStr = ciphertext.slice(0,16);
    var cipher = ciphertext.slice(16);
    var iv = Buffer.from(ivStr,'binary');
    var decipher = crypto.createDecipheriv('aes-256-ctr', key, iv);
    var dec = decipher.update(cipher,'hex','utf8')
    dec += decipher.final('utf8');

    return JSON.parse(dec);
};





exports.generateEncryptionKey = function(){
    return crypto.randomBytes(32);
};


