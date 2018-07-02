const crypto = require('crypto');
const fs = require('fs');
var ecdsa = require('./ecdsa/lib/ECDSA').createECDSA();

var algorithm = 'aes-256-gcm';
var defaultPin = '12345678';
var defaultDSeedPath = './.privateSky/dseed';
exports.generateECDSAKeyPair = function(){
    return ecdsa.generateKeyPair();
};


exports.sign = function(privateKey, digest){
    return ecdsa.sign(privateKey,digest);
};

exports.verify = function(publicKey, signature, digest){
    return ecdsa.verify(publicKey, signature, digest);
};

function generateSalt(inputData, saltLen){
    var hash = crypto.createHash('sha512');
    hash.update(inputData);
    var digest = Buffer.from(hash.digest('hex'), 'binary');

    var salt = digest.slice(0, saltLen);

    return salt;
}

function encrypt(data, password){
    var keySalt = crypto.randomBytes(32);
    var key = crypto.pbkdf2Sync(password, keySalt, 10000, 32, 'sha512');

    var aadSalt = crypto.randomBytes(32);
    var aad = crypto.pbkdf2Sync(password, aadSalt, 10000, 32, 'sha512');

    var salt = Buffer.concat([keySalt, aadSalt]);
    var iv = crypto.pbkdf2Sync(password, salt, 10000, 12, 'sha512');

    var cipher = crypto.createCipheriv(algorithm, key, iv);
    cipher.setAAD(aad);
    var encryptedText = cipher.update(data,'binary');
    var final = Buffer.from(cipher.final('binary'),'binary');

    var tag = cipher.getAuthTag();

    encryptedText = Buffer.concat([encryptedText, final]);
    var cipherText =  Buffer.concat([salt, encryptedText, tag]);

    return cipherText;
}

function decrypt(encryptedData, password){
    var salt = encryptedData.slice(0, 64);
    var keySalt = salt.slice(0, 32);
    var aadSalt = salt.slice(-32);

    var iv = crypto.pbkdf2Sync(password, salt, 10000, 12, 'sha512');
    var key = crypto.pbkdf2Sync(password, keySalt, 10000, 32, 'sha512');
    var aad = crypto.pbkdf2Sync(password, aadSalt, 10000, 32, 'sha512');

    var ciphertext = encryptedData.slice(64, encryptedData.length - 16);
    var tag = encryptedData.slice(-16);

    var decipher = crypto.createDecipheriv(algorithm, key, iv);

    decipher.setAuthTag(tag);
    decipher.setAAD(aad);

    var plaintext = Buffer.from(decipher.update(ciphertext, 'binary'), 'binary');
    var final = Buffer.from(decipher.final('binary'), 'binary');
    plaintext = Buffer.concat([plaintext, final]);

    return plaintext;
}


function deriveKey(password, iterations, dkLen) {
    iterations = iterations || 10000;
    dkLen = dkLen || 32;
    var salt = generateSalt(password, 32);
    var dk = crypto.pbkdf2Sync(password, salt, iterations, dkLen, 'sha512');
    return Buffer.from(dk);
}
exports.saveDerivedSeed = function(seed, pin, dseedLen, folderPath){
    folderPath = folderPath || './.privateSky/';
    pin = pin || defaultPin;
    var dseed = deriveKey(seed, null, dseedLen);
    var encryptedDSeed = encrypt(dseed, pin);

    if(!fs.existsSync(folderPath)){
        fs.mkdirSync(folderPath);
    }
    fs.writeFileSync(folderPath + 'dseed', encryptedDSeed);


};

exports.setPin = function(pin, dseedPath){
    dseedPath = dseedPath || defaultDSeedPath;
    var oldPin = defaultPin;
    var encryptedDSeed = fs.readFileSync(dseedPath);
    var dseed = decrypt(encryptedDSeed, oldPin);

    encryptedDSeed = encrypt(dseed, pin);
    fs.writeFileSync(dseedPath, encryptedDSeed);

};
exports.encryptJson = function(data, pin, dseedPath){
    pin = pin || defaultPin;
    dseedPath = dseedPath || defaultDSeedPath;
    var encryptedDSeed = fs.readFileSync(dseedPath);

    // var dpin = deriveKey(pin, null, null);
    var dseed = decrypt(encryptedDSeed, pin);

    var cipherText = encrypt(JSON.stringify(data), dseed);


    return cipherText;
};


exports.decryptJson = function(encryptedData, pin, dseedPath){
    pin = pin || defaultPin;
    dseedPath = dseedPath || defaultDSeedPath;
    var encryptedDSeed = fs.readFileSync(dseedPath);


    var dseed = decrypt(encryptedDSeed, pin);
    var plaintext = decrypt(encryptedData, dseed);

    return JSON.parse(plaintext);
};

exports.encryptBlob = function (data, pin, dseedPath) {
    pin = pin || defaultPin;
    dseedPath = dseedPath || defaultDSeedPath;
    var encryptedDSeed = fs.readFileSync(dseedPath);
    var dseed = decrypt(encryptedDSeed, pin);
    var ciphertext = encrypt(data, dseed);

    return ciphertext;
};

exports.decryptBlob = function (encryptedData, pin, dseedPath) {
    pin = pin || defaultPin;
    dseedPath = dseedPath || defaultDSeedPath;
    var encryptedDSeed = fs.readFileSync(dseedPath);
    var dseed = decrypt(encryptedDSeed, pin);

    var plaintext = decrypt(encryptedData, dseed);

    return plaintext;
};



exports.generateSeed = function(){
    var seed = crypto.randomBytes(32);
    return Buffer.from(seed);
};
