
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
function PskCrypto() {
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
	const utils = require("./utils/cryptoUtils");
	const archiver = require("./psk-archiver");
	var tempFolder = os.tmpdir();

	this.encryptStream = function (inputPath, destinationPath, password, callback) {
		utils.encryptFile(inputPath, destinationPath, password, function (err) {
			callback(err);
		});
	};

	this.decryptStream = function (encryptedInputPath, outputFolder, password, callback) {
		utils.decryptFile(encryptedInputPath, tempFolder, password, function (err, tempArchivePath) {
			if(err){
				return callback(err);
			}
			archiver.unzipStream(tempArchivePath, outputFolder, function (err) {
				if(err){
					return callback(err);
				}
				utils.deleteRecursively(tempArchivePath, function (err) {
					callback(err);
				});

			});
		})
	};

	this.encryptJson = function (inputObj, dseed, depth, callback) {
		utils.encryptObjectInMemory(inputObj, dseed, depth, function (err, encryptedObj) {
			if(err){
				return callback(err);
			}
			callback(null, encryptedObj);
		});
	};

	this.decryptJson = function (encryptedData, dseed, callback) {
		utils.decryptObjectInMemory(encryptedData, dseed, function (err, obj) {
			if(err){
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


	this.generateSafeUid = function (password) {
		password = password || Buffer.alloc(0);

		return utils.encode(this.pskHash(password));
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

}

module.exports = new PskCrypto();
