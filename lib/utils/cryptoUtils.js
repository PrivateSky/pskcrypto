const crypto = require('crypto');
const fs = require('fs');
const path = require("path");
const PskArchiver = require("../psk-archiver");
const algorithm = 'aes-256-gcm';


const iterations_number = 1000;

function encode(buffer) {
	return buffer.toString('base64')
		.replace(/\+/g, '')
		.replace(/\//g, '')
		.replace(/=+$/, '');
}

function deleteRecursively(inputPath, callback) {

	fs.stat(inputPath, function (err, stats) {
		if (err) {
			callback(err, stats);
			return;
		}
		if (stats.isFile()) {
			fs.unlink(inputPath, function (err) {
				if (err) {
					callback(err, null);
				} else {
					callback(null, true);
				}
			});
		} else if (stats.isDirectory()) {
			fs.readdir(inputPath, function (err, files) {
				if (err) {
					callback(err, null);
					return;
				}
				const f_length = files.length;
				let f_delete_index = 0;

				const checkStatus = function () {
					if (f_length === f_delete_index) {
						fs.rmdir(inputPath, function (err) {
							if (err) {
								callback(err, null);
							} else {
								callback(null, true);
							}
						});
						return true;
					}
					return false;
				};
				if (!checkStatus()) {
					files.forEach(function (file) {
						const tempPath = path.join(inputPath, file);
						deleteRecursively(tempPath, function removeRecursiveCB(err, status) {
							if (!err) {
								f_delete_index++;
								checkStatus();
							} else {
								callback(err, null);
							}
						});
					});
				}
			});
		}
	});
}





function createPskHash(data) {
	const pskHash = new PskHash();
	pskHash.update(data);
	return pskHash.digest();
}

function PskHash() {
	const sha512 = crypto.createHash('sha512');
	const sha256 = crypto.createHash('sha256');

	function update(data) {
		sha512.update(data);
	}

	function digest() {
		sha256.update(sha512.digest());
		return sha256.digest();
	}

	return {
		update,
		digest
	}
}


function generateSalt(inputData, saltLen) {
	const hash = crypto.createHash('sha512');
	hash.update(inputData);
	const digest = Buffer.from(hash.digest('hex'), 'binary');

	return digest.slice(0, saltLen);
}

function encrypt(data, password) {
	const keySalt = crypto.randomBytes(32);
	const key = crypto.pbkdf2Sync(password, keySalt, iterations_number, 32, 'sha512');

	const aadSalt = crypto.randomBytes(32);
	const aad = crypto.pbkdf2Sync(password, aadSalt, iterations_number, 32, 'sha512');

	const salt = Buffer.concat([keySalt, aadSalt]);
	const iv = crypto.pbkdf2Sync(password, salt, iterations_number, 12, 'sha512');

	const cipher = crypto.createCipheriv(algorithm, key, iv);
	cipher.setAAD(aad);
	let encryptedText = cipher.update(data, 'binary');
	const final = Buffer.from(cipher.final('binary'), 'binary');
	const tag = cipher.getAuthTag();

	encryptedText = Buffer.concat([encryptedText, final]);

	return Buffer.concat([salt, encryptedText, tag]);
}

function decrypt(encryptedData, password) {
	const salt = encryptedData.slice(0, 64);
	const keySalt = salt.slice(0, 32);
	const aadSalt = salt.slice(-32);

	const iv = crypto.pbkdf2Sync(password, salt, iterations_number, 12, 'sha512');
	const key = crypto.pbkdf2Sync(password, keySalt, iterations_number, 32, 'sha512');
	const aad = crypto.pbkdf2Sync(password, aadSalt, iterations_number, 32, 'sha512');

	const ciphertext = encryptedData.slice(64, encryptedData.length - 16);
	const tag = encryptedData.slice(-16);

	const decipher = crypto.createDecipheriv(algorithm, key, iv);
	decipher.setAuthTag(tag);
	decipher.setAAD(aad);

	let plaintext = Buffer.from(decipher.update(ciphertext, 'binary'), 'binary');
	const final = Buffer.from(decipher.final('binary'), 'binary');
	plaintext = Buffer.concat([plaintext, final]);
	return plaintext;
}

function encryptObjectInMemory(inputObj, password, depth, callback) {
	const archiver = new PskArchiver();

	archiver.zipInMemory(inputObj, depth, function (err, zippedObj) {
		if (err) {
			return callback(err);
		}
		const cipherText = encrypt(zippedObj, password);
		callback(null, cipherText);
	})
}

function decryptObjectInMemory(encryptedObject, password, callback) {
	const archiver = new PskArchiver();

	const zippedObject = decrypt(encryptedObject, password);
	archiver.unzipInMemory(zippedObject, function (err, obj) {
		if (err) {
			return callback(err);
		}
		callback(null, obj);
	})
}


module.exports = {
	createPskHash,
	encrypt,
	encryptObjectInMemory,
	decrypt,
	decryptObjectInMemory,
	deleteRecursively,
	encode,
	generateSalt,
	iterations_number,
	algorithm,
	PskHash
};

