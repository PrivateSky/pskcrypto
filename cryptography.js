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
    var iv = Buffer.from(crypto.randomBytes(16));
    var cipher = crypto.createCipheriv('aes-256-cfb', encryptionKey, iv);
    var ciphertext = Buffer.from(cipher.update(dseed, 'binary'), 'binary');
    var final = Buffer.from(cipher.final('binary'), 'binary');
    ciphertext = Buffer.concat([iv, ciphertext, final]);

    return ciphertext;
}

function decryptDSeed(encryptedDSeed, encryptionKey) {
    var iv = encryptedDSeed.slice(0, 16);
    var seedDechiper = crypto.createDecipheriv('aes-256-cfb', encryptionKey, iv);
    var toBeDecrypted = encryptedDSeed.slice(16);
    var dseed = Buffer.from(seedDechiper.update(toBeDecrypted,'binary'), 'binary');
    var final = Buffer.from(seedDechiper.final('binary'), 'binary');

    var dseed = Buffer.concat([dseed, final]);

    return dseed;
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
    var seedSalt = generateSalt(seed, 32);
    var dseed = deriveKey(seed, null, dseedLen);

    var dpin = deriveKey(pin, null, null);
    var encryptedDSeed = encryptDSeed(dseed, dpin);

    if(!fs.existsSync(folderPath)){
        fs.mkdirSync(folderPath);
    }
    fs.writeFileSync(folderPath + 'dseed', encryptedDSeed);


};

exports.setPin = function(pin, dseedLen, dseedPath){
    dseedLen = dseedLen || 32;
    dseedPath = dseedPath || defaultDSeedPath;
    var oldPin = defaultPin;
    var encryptionKey = deriveKey(oldPin, null, null);
    var encryptedDSeed = fs.readFileSync(dseedPath);
    var dseed = decryptDSeed(encryptedDSeed, encryptionKey);

    encryptionKey = deriveKey(pin, null, null);
    encryptedDSeed = encryptDSeed(dseed, encryptionKey);
    fs.writeFileSync(dseedPath, encryptedDSeed);

};
exports.encryptJson = function(data, pin, dseedPath){
    pin = pin || defaultPin;
    dseedPath = dseedPath || defaultDSeedPath;
    var encryptedDSeed = fs.readFileSync(dseedPath);

    var dpin = deriveKey(pin, null, null);
    var dseed = decryptDSeed(encryptedDSeed, dpin);
    var keySalt = crypto.randomBytes(32);
    var key = crypto.pbkdf2Sync(dseed, keySalt, 10000, 32, 'sha512');

    var aadSalt = crypto.randomBytes(32);
    var aad = crypto.pbkdf2Sync(dseed, aadSalt, 10000, 32, 'sha512');

    var salt = Buffer.concat([keySalt, aadSalt]);
    var iv = crypto.pbkdf2Sync(dseed, salt, 10000, 12, 'sha512');

    var bufferedData = Buffer.from(JSON.stringify(data), 'binary');
    var cipher = crypto.createCipheriv(algorithm, key, iv);
    cipher.setAAD(aad);
    var encryptedText = cipher.update(bufferedData,'binary');
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
    var dpin = deriveKey(pin, null, null);

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



exports.generateSeed = function(){
    var seed = crypto.randomBytes(32);
    return Buffer.from(seed);
};



