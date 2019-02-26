
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');

const utils = require("./utils/cryptoUtils");
const PskArchiver = require("./psk-archiver");
const EventEmitter = require('events');
const inherits = require('util').inherits;

const tempFolder = os.tmpdir();

inherits(PskCrypto, EventEmitter);

function PskCrypto() {

	EventEmitter.call(this);
	
	/*--------------------------------------------- ECDSA functions ------------------------------------------*/
	const ecdsa = require("./ECDSA").createECDSA();
	this.generateECDSAKeyPair = function () {
		return ecdsa.generateKeyPair();
	};

	this.sign = function (privateKey, digest) {
		return ecdsa.sign(privateKey, digest);
	};

	this.verify = function (publicKey, signature, digest) {
		return ecdsa.verify(publicKey, signature, digest);
	};

	/*---------------------------------------------Encryption functions -------------------------------------*/

	this.encryptStream = function (inputPath, destinationPath, password, callback) {
		const archiver = new PskArchiver();

		archiver.on('progress', (progress) => {
			console.log("progress", progress);
		});

		archiver.once('total', (totalSize) => {
			console.log("received Total size", totalSize);
		});

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
				const key = crypto.pbkdf2Sync(password, keySalt, utils.iterations_number, 32, 'sha512');

				const aadSalt = crypto.randomBytes(32);
				const aad = crypto.pbkdf2Sync(password, aadSalt, utils.iterations_number, 32, 'sha512');

				const salt = Buffer.concat([keySalt, aadSalt]);
				const iv = crypto.pbkdf2Sync(password, salt, utils.iterations_number, 12, 'sha512');

				const cipher = crypto.createCipheriv(utils.algorithm, key, iv);
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
	};

	this.decryptStream = function (encryptedInputPath, outputFolder, password, callback) {

		const archiver = new PskArchiver();

		utils.decryptFile(encryptedInputPath, tempFolder, password, function (err, tempArchivePath) {
			if(err){
				return callback(err);
			}

			archiver.on('progress', (progress) => {
				console.log("prog", progress);
			});


			archiver.unzipStream(tempArchivePath, outputFolder, function (err, unzippedFileNames) {
				if(err){
					return callback(err);
				}

				utils.deleteRecursively(tempArchivePath, function (err) {
					if(err){
						return callback(err);
					}

					callback(undefined, unzippedFileNames);
				});

			});
		})
	};

	this.encryptObject = function (inputObj, dseed, depth, callback) {
		const archiver = new PskArchiver();

		archiver.zipInMemory(inputObj, depth, function (err, zippedObj) {
			if (err) {
				return callback(err);
			}
			const cipherText = utils.encrypt(zippedObj, dseed);
			callback(null, cipherText);
		})
	};

	this.decryptObject = function (encryptedData, dseed, callback) {
		const archiver = new PskArchiver();

		const zippedObject = utils.decrypt(encryptedData, dseed);
		archiver.unzipInMemory(zippedObject, function (err, obj) {
			if (err) {
				return callback(err);
			}
			callback(null, obj);
		})
	};

	this.pskHash = function (data) {
		if (Buffer.isBuffer(data)) {
			return utils.createPskHash(data);
		}
		if (data instanceof Object) {
			return utils.createPskHash(JSON.stringify(data));
		}
		return utils.createPskHash(data);
	};

	this.pskHashStream = function (readStream, callback) {
		const pskHash = new utils.PskHash();

		readStream.on('data', (chunk) => {
			pskHash.update(chunk);
		});


		readStream.on('end', () => {
			callback(null, pskHash.digest());
		})
	};


	this.saveData = function (data, password, path, callback) {
		const encryptionKey = this.deriveKey(password, null, null);
		const iv = crypto.randomBytes(16);
		const cipher = crypto.createCipheriv('aes-256-cfb', encryptionKey, iv);
		let encryptedDSeed = cipher.update(data, 'binary');
		const final = Buffer.from(cipher.final('binary'), 'binary');
		encryptedDSeed      = Buffer.concat([iv, encryptedDSeed, final]);
		fs.writeFile(path, encryptedDSeed, function (err) {
			callback(err);
		});
	};


	this.loadData = function (password, path, callback) {

		fs.readFile(path, null, (err, encryptedData) => {
			if(err){
				callback(err);
			}else{
				const iv = encryptedData.slice(0, 16);
				const encryptedDseed = encryptedData.slice(16);
				const encryptionKey = this.deriveKey(password, null, null);
				const decipher = crypto.createDecipheriv('aes-256-cfb', encryptionKey, iv);
				let dseed = Buffer.from(decipher.update(encryptedDseed, 'binary'), 'binary');
				const final = Buffer.from(decipher.final('binary'), 'binary');
				dseed              = Buffer.concat([dseed, final]);
				callback(null, dseed);
			}
		});
	};


	this.generateSafeUid = function (password, additionalData) {
		password = password || Buffer.alloc(0);
		if(!additionalData) {
			additionalData = Buffer.alloc(0);
		}

		if(!Buffer.isBuffer(additionalData)) {
			additionalData = Buffer.from(additionalData);
		}

		return utils.encode(this.pskHash(Buffer.concat([password, additionalData])));
	};

	this.deriveKey = function deriveKey(password, iterations, dkLen) {
		iterations = iterations || 1000;
		dkLen      = dkLen || 32;
		const salt   = utils.generateSalt(password, 32);
		const dk     = crypto.pbkdf2Sync(password, salt, iterations, dkLen, 'sha512');
		return Buffer.from(dk);
	};

	this.randomBytes = crypto.randomBytes;
	this.PskHash = utils.PskHash;

	function emitProgress() {
		
	}

}

module.exports = new PskCrypto();
