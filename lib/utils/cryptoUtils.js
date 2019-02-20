const crypto = require('crypto');
const fs = require('fs');
const path = require("path");
const archiver = require("../psk-archiver");
const algorithm = 'aes-256-gcm';

const iterations_number = 3000;

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

function encryptFile(inputPath, destinationPath, password, callback) {
	fs.open(destinationPath, "wx", function (err, fd) {
		if (err) {
			callback(err);
			return;
		}

		fs.close(fd, function (err) {
			if (err) {
				return callback(err);
			}

			const ws = fs.createWriteStream(destinationPath, {autoClose: false});
			const keySalt = crypto.randomBytes(32);
			const key = crypto.pbkdf2Sync(password, keySalt, iterations_number, 32, 'sha512');

			const aadSalt = crypto.randomBytes(32);
			const aad = crypto.pbkdf2Sync(password, aadSalt, iterations_number, 32, 'sha512');

			const salt = Buffer.concat([keySalt, aadSalt]);
			const iv = crypto.pbkdf2Sync(password, salt, iterations_number, 12, 'sha512');

			const cipher = crypto.createCipheriv(algorithm, key, iv);
			cipher.setAAD(aad);
			archiver.zipStream(inputPath, cipher, function (err, cipherStream) {

				if (err) {
					return callback(err);
				}

				cipherStream.on("data", function (chunk) {
					ws.write(chunk);
				});
				cipherStream.on('end', function () {
					const tag = cipher.getAuthTag();
					const dataToAppend = Buffer.concat([salt, tag]);
					ws.end(dataToAppend, function (err) {
						if (err) {
							return callback(err);
						}
						callback();
					})
				});
			});
		});
	});
}

function decryptFile(encryptedInputPath, tempFolder, password, callback) {
	fs.stat(encryptedInputPath, function (err, stats) {
		if (err) {
			callback(err, null);
		} else {
			const fileSizeInBytes = stats.size;
			fs.open(encryptedInputPath, "r", function (err, fd) {
				if (err) {
					callback(err, null);
				} else {
					const encryptedAuthData = Buffer.alloc(80);

					fs.read(fd, encryptedAuthData, 0, 80, fileSizeInBytes - 80, function (err, bytesRead) {
						const salt = encryptedAuthData.slice(0, 64);
						const keySalt = salt.slice(0, 32);
						const aadSalt = salt.slice(-32);

						const iv = crypto.pbkdf2Sync(password, salt, iterations_number, 12, 'sha512');
						const key = crypto.pbkdf2Sync(password, keySalt, iterations_number, 32, 'sha512');
						const aad = crypto.pbkdf2Sync(password, aadSalt, iterations_number, 32, 'sha512');
						const tag = encryptedAuthData.slice(-16);

						const decipher = crypto.createDecipheriv(algorithm, key, iv);

						decipher.setAAD(aad);
						decipher.setAuthTag(tag);
						const rs = fs.createReadStream(encryptedInputPath, {start: 0, end: fileSizeInBytes - 81});
						$$.ensureFolderExists(tempFolder, function (err) {
							if (!err) {
								const tempArchivePath = path.join(tempFolder, path.basename(encryptedInputPath) + ".zip");

								fs.open(tempArchivePath, "wx", function (err, fd) {
									if (err) {
										callback(err);
										return;
									}

									fs.close(fd, function (err) {

										if (!err) {
											const ws = fs.createWriteStream(tempArchivePath, {autoClose: false});
											ws.on("finish", function () {
												callback(null, tempArchivePath);
											});
											rs.pipe(decipher).pipe(ws);
										}

									});
								});

							}
						})

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


function isJson(data) {
	try {
		JSON.parse(data);
	} catch (e) {
		return false;
	}
	return true;
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
	archiver.zipInMemory(inputObj, depth, function (err, zippedObj) {
		if (err) {
			return callback(err);
		}
		const cipherText = encrypt(zippedObj, password);
		callback(null, cipherText);
	})
}

function decryptObjectInMemory(encryptedObject, password, callback) {
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
	encryptFile,
	encryptObjectInMemory,
	decrypt,
	decryptFile,
	decryptObjectInMemory,
	deleteRecursively,
	encode,
	generateSalt,
	isJson,
	PskHash
};

