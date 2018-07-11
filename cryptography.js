const crypto = require('crypto');
const fs = require('fs');
const ecdsa = require('./ecdsa/lib/ECDSA').createECDSA();
const algorithm = 'aes-256-gcm';

exports.generateECDSAKeyPair = function(){
	return ecdsa.generateKeyPair();
};

exports.sign = function(privateKey, digest){
	return ecdsa.sign(privateKey,digest);
};

exports.verify = function(publicKey, signature, digest){
	return ecdsa.verify(publicKey, signature, digest);
};

function createHash(data){
	var hash = crypto.createHash('sha512');
	hash.update(data);
	return hash.digest();
}

exports.hashJson = function (data) {
	var serializedData = JSON.stringify(data);
	return createHash(serializedData);
};

exports.hashBlob = function (data) {
	return createHash(data);
};

function generateSalt(inputData, saltLen){
	var hash   = crypto.createHash('sha512');
	hash.update(inputData);
	var digest = Buffer.from(hash.digest('hex'), 'binary');

	return digest.slice(0, saltLen);
}

function encrypt(data, password){
	var keySalt       = crypto.randomBytes(32);
	var key           = crypto.pbkdf2Sync(password, keySalt, 10000, 32, 'sha512');

	var aadSalt       = crypto.randomBytes(32);
	var aad           = crypto.pbkdf2Sync(password, aadSalt, 10000, 32, 'sha512');

	var salt          = Buffer.concat([keySalt, aadSalt]);
	var iv            = crypto.pbkdf2Sync(password, salt, 10000, 12, 'sha512');

	var cipher        = crypto.createCipheriv(algorithm, key, iv);
	cipher.setAAD(aad);
	var encryptedText = cipher.update(data,'binary');
	var final = Buffer.from(cipher.final('binary'),'binary');
	var tag = cipher.getAuthTag();

	encryptedText = Buffer.concat([encryptedText, final]);

	return Buffer.concat([salt, encryptedText, tag]);
}

function decrypt(encryptedData, password){
	var salt       = encryptedData.slice(0, 64);
	var keySalt    = salt.slice(0, 32);
	var aadSalt    = salt.slice(-32);

	var iv         = crypto.pbkdf2Sync(password, salt, 10000, 12, 'sha512');
	var key        = crypto.pbkdf2Sync(password, keySalt, 10000, 32, 'sha512');
	var aad        = crypto.pbkdf2Sync(password, aadSalt, 10000, 32, 'sha512');

	var ciphertext = encryptedData.slice(64, encryptedData.length - 16);
	var tag        = encryptedData.slice(-16);

	var decipher   = crypto.createDecipheriv(algorithm, key, iv);
	decipher.setAuthTag(tag);
	decipher.setAAD(aad);

	var plaintext  = Buffer.from(decipher.update(ciphertext, 'binary'), 'binary');
	var final      = Buffer.from(decipher.final('binary'), 'binary');
	plaintext      = Buffer.concat([plaintext, final]);

	return plaintext;
}

exports.encryptDSeed = function(dseed, pin, dseedPath) {
	var encryptionKey  = deriveKey(pin, null, null);
	var iv             = crypto.randomBytes(16);
	var cipher         = crypto.createCipheriv('aes-256-cfb', encryptionKey, iv);
	var encryptedDSeed = cipher.update(dseed,'binary');
	var final          = Buffer.from(cipher.final('binary'),'binary');
	encryptedDSeed     = Buffer.concat([iv, encryptedDSeed, final]);
	fs.writeFileSync(dseedPath, encryptedDSeed);
};

exports.decryptDseed = function(pin, dseedPath) {
	var encryptedData  = fs.readFileSync(dseedPath);
	var iv             = encryptedData.slice(0,16);
	var encryptedDseed = encryptedData.slice(16);
	var encryptionKey  = deriveKey(pin, null, null);
	var decipher       = crypto.createDecipheriv('aes-256-cfb', encryptionKey, iv);
	var dseed          = Buffer.from(decipher.update(encryptedDseed, 'binary'), 'binary');
	var final          = Buffer.from(decipher.final('binary'), 'binary');
	dseed              = Buffer.concat([dseed, final]);

	return dseed;

};

function deriveKey(password, iterations, dkLen) {
	iterations = iterations || 10000;
	dkLen      = dkLen || 32;
	var salt   = generateSalt(password, 32);
	var dk     = crypto.pbkdf2Sync(password, salt, iterations, dkLen, 'sha512');
	return Buffer.from(dk);
}
exports.deriveSeed = function (seed, dseedLen) {
	return deriveKey(seed, null, dseedLen);

};

exports.encryptJson = function(data, pin, dseedPath){
	var dseed       = exports.decryptDseed(pin, dseedPath);
	var cipherText  = encrypt(JSON.stringify(data), dseed);

	return cipherText;
};

exports.decryptJson = function(encryptedData, pin, dseedPath){
	var dseed     = exports.decryptDseed(pin, dseedPath);
	var plaintext = decrypt(encryptedData, dseed);

	return JSON.parse(plaintext);
};

exports.encryptBlob = function (data, pin, dseedPath) {
	var dseed       = exports.decryptDseed(pin, dseedPath);
	var ciphertext  = encrypt(data, dseed);

	return ciphertext;
};

exports.decryptBlob = function (encryptedData, pin, dseedPath) {
	var dseed       = exports.decryptDseed(pin, dseedPath);
	var plaintext   = decrypt(encryptedData, dseed);

	return plaintext;
};

exports.generateSeed = function(){
	return crypto.randomBytes(32);
};
