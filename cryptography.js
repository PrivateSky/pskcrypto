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

function encryptDSeed(dseed, encryptionKey){
    var cipher = crypto.createCipher('aes-256-cfb', encryptionKey);
    var ciphertext = cipher.update(dseed, 'binary');
    var final = Buffer.from(cipher.final('binary'), 'binary');
    ciphertext = Buffer.concat([ciphertext, final]);

    return ciphertext;
}

function decryptDSeed(encryptedDSeed, encryptionKey) {
    var seedDechiper = crypto.createDecipher('aes-256-cfb', encryptionKey);
    var dseed = Buffer.from(seedDechiper.update(encryptedDSeed,'hex','binary'));
    var final = Buffer.from(seedDechiper.final('binary'));

    var dseed = Buffer.concat([dseed, final]);

    return dseed;
}

exports.saveDerivedSeed = function(seed, pin, dseedLen, folderPath){
    folderPath = folderPath || './.privateSky/';
    var seedSalt = generateSalt(seed, 32);
    var dseed = crypto.pbkdf2Sync(seed, seedSalt, 10000, dseedLen, 'sha512');
    var pinSalt = generateSalt(pin, 32);
    var dpin = crypto.pbkdf2Sync(pin, pinSalt, 10000, 32, 'sha512');
    var encryptedDSeed = encryptDSeed(dseed, dpin);

    if(!fs.existsSync(folderPath)){
        fs.mkdirSync(folderPath);
    }
    fs.writeFileSync(folderPath + 'dseed', encryptedDSeed);


};

exports.setPin = function(pin, dseedPath){
    dseedPath = dseedPath || defaultDSeedPath;
    var oldPin = defaultPin;
    var oldPinSalt = generateSalt(oldPin, 32);
    var encryptionKey = crypto.pbkdf2Sync(oldPin, oldPinSalt, 10000, 32, 'sha512');
    var encryptedDSeed = fs.readFileSync(dseedPath);
    var dseed = decryptDSeed(encryptedDSeed, encryptionKey);
    var pinSalt = generateSalt(pin, 32);
    encryptionKey = crypto.pbkdf2Sync(pin, pinSalt, 10000, 32, 'sha512');
    encryptedDSeed = encryptDSeed(dseed, encryptionKey);
    fs.writeFileSync(dseedPath, encryptedDSeed);

};
exports.encryptJson = function(data, pin, dseedPath){
    pin = pin || defaultPin;
    dseedPath = dseedPath || defaultDSeedPath;
    var encryptedDSeed = fs.readFileSync(dseedPath);
    var pinSalt = generateSalt(pin, 32);
    var dpin = crypto.pbkdf2Sync(pin, pinSalt, 10000, 32, 'sha512');

    var dseed = decryptDSeed(encryptedDSeed, dpin);

    var keySalt = crypto.randomBytes(32);
    var key = crypto.pbkdf2Sync(dseed, keySalt, 10000, 32, 'sha512');

    var aadSalt = crypto.randomBytes(32);
    var aad = crypto.pbkdf2Sync(dseed, aadSalt, 10000, 32, 'sha512');

    var salt = Buffer.concat([keySalt, aadSalt]);
    var iv = crypto.pbkdf2Sync(dseed, salt, 10000, 12, 'sha512');

    var buf = Buffer.from(JSON.stringify(data), 'binary');
    var cipher = crypto.createCipheriv(algorithm, key, iv);
    cipher.setAAD(aad);
    var encryptedText = cipher.update(buf,'binary');
    var final = Buffer.from(cipher.final('binary'),'binary');

    var tag = cipher.getAuthTag();

    encryptedText = Buffer.concat([encryptedText, final]);
    var cipherText = [iv, salt, encryptedText, tag];


    return Buffer.concat(cipherText);
};


exports.decryptJson = function(encryptedData, pin, dseedPath){
    pin = pin || defaultPin;
    dseedPath = dseedPath || defaultDSeedPath;
    var encryptedDSeed = fs.readFileSync(dseedPath);
    var pinSalt = generateSalt(pin, 32);
    var dpin = crypto.pbkdf2Sync(pin, pinSalt, 10000, 32, 'sha512');

    var dseed = decryptDSeed(encryptedDSeed, dpin);

    var iv = encryptedData.slice(0, 12);
    var salt = encryptedData.slice(12, 76);
    var keySalt = salt.slice(0, 32);
    var aadSalt = salt.slice(-32);

    var key = crypto.pbkdf2Sync(dseed, keySalt, 10000, 32, 'sha512');
    var aad = crypto.pbkdf2Sync(dseed, aadSalt, 10000, 32, 'sha512');

    var ciphertext = encryptedData.slice(76, encryptedData.length - 16);
    var tag = encryptedData.slice(-16);

    var decipher = crypto.createDecipheriv(algorithm, key, iv);

    decipher.setAuthTag(tag);
    decipher.setAAD(aad);

    var dec = Buffer.from(decipher.update(ciphertext,'hex','binary'), 'binary');
    var final = Buffer.from(decipher.final('binary'), 'binary');
    dec = Buffer.concat([dec, final]);

    return JSON.parse(dec);
};

exports.encryptBlob = function (data, pin, dseedPath) {
    pin = pin || defaultPin;
    dseedPath = dseedPath || defaultDSeedPath;
    var encryptedDSeed = fs.readFileSync(dseedPath);
    var pinSalt = generateSalt(pin, 32);
    var dpin = crypto.pbkdf2Sync(pin, pinSalt, 10000, 32, 'sha512');
    var dseed = decryptDSeed(encryptedDSeed, dpin);

    var keySalt = crypto.randomBytes(32);
    var key = crypto.pbkdf2Sync(dseed, keySalt, 10000, 32, 'sha512');

    var aadSalt = crypto.randomBytes(32);
    var aad = crypto.pbkdf2Sync(dseed, aadSalt, 10000, 32, 'sha512');

    var salt = Buffer.concat([keySalt, aadSalt]);
    var iv = crypto.pbkdf2Sync(dseed, salt, 10000, 12, 'sha512');

    var cipher = crypto.createCipheriv(algorithm, key, iv);
    cipher.setAAD(aad);
    var encryptedBlob = cipher.update(data,'binary');
    var final = Buffer.from(cipher.final('binary'),'binary');

    var tag = cipher.getAuthTag();

    encryptedBlob = Buffer.concat([encryptedBlob, final]);
    var cipherText = [iv, salt, encryptedBlob, tag];


    return Buffer.concat(cipherText);
};

exports.decryptBlob = function (encryptedData, pin, dseedPath) {
    pin = pin || defaultPin;
    dseedPath = dseedPath || defaultDSeedPath;
    var encryptedDSeed = fs.readFileSync(dseedPath);
    var pinSalt = generateSalt(pin, 32);
    var dpin = crypto.pbkdf2Sync(pin, pinSalt, 10000, 32, 'sha512');
    var dseed = decryptDSeed(encryptedDSeed, dpin);
    var iv = encryptedData.slice(0, 12);
    var salt = encryptedData.slice(12, 76);
    var keySalt = salt.slice(0, 32);
    var aadSalt = salt.slice(-32);

    var key = crypto.pbkdf2Sync(dseed, keySalt, 10000, 32, 'sha512');
    var aad = crypto.pbkdf2Sync(dseed, aadSalt, 10000, 32, 'sha512');

    var ciphertext = encryptedData.slice(76, encryptedData.length - 16);
    var tag = encryptedData.slice(-16);

    var decipher = crypto.createDecipheriv(algorithm, key, iv);

    decipher.setAuthTag(tag);
    decipher.setAAD(aad);

    var dec = Buffer.from(decipher.update(ciphertext,'hex','binary'), 'binary');
    var final = Buffer.from(decipher.final('binary'), 'binary');
    dec = Buffer.concat([dec, final]);

    return dec;
};



exports.generateEncryptionKey = function(){
    return crypto.randomBytes(32);
};


