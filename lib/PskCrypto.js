
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

	this.generateSeed = function (backupUrl) {
		const seed = 's' + crypto.randomBytes(32).toString("hex") + backupUrl;

		return Buffer.from(seed);
	};

	this.deriveSeed = function (seed, dseedLen) {
		const strSeed = seed.toString();
		const backupUrl = strSeed.substring(33);
		const dseed =  'd' + utils.deriveKey(seed, null, dseedLen).toString() + backupUrl;
		return Buffer.from(dseed);

	};

	this.saveDSeed = function (dseed, pin, dseedPath, callback) {
		const encryptionKey = utils.deriveKey(pin, null, null);
		const iv = crypto.randomBytes(16);
		const cipher = crypto.createCipheriv('aes-256-cfb', encryptionKey, iv);
		let encryptedDSeed = cipher.update(dseed, 'binary');
		const final = Buffer.from(cipher.final('binary'), 'binary');
		encryptedDSeed      = Buffer.concat([iv, encryptedDSeed, final]);
		fs.writeFile(dseedPath, encryptedDSeed, function (err) {
			callback(err);
		});
	};


	this.loadDseed = function (pin, dseedPath, callback) {

		fs.readFile(dseedPath, null, function (err, encryptedData) {
			if(err){
				callback(err);
			}else{
				const iv = encryptedData.slice(0, 16);
				const encryptedDseed = encryptedData.slice(16);
				const encryptionKey = utils.deriveKey(pin, null, null);
				const decipher = crypto.createDecipheriv('aes-256-cfb', encryptionKey, iv);
				let dseed = Buffer.from(decipher.update(encryptedDseed, 'binary'), 'binary');
				const final = Buffer.from(decipher.final('binary'), 'binary');
				dseed              = Buffer.concat([dseed, final]);
				callback(null, dseed);
			}
		});
	};


	this.generateSafeUid = function (dseed, path) {
		path = path || process.cwd();
		dseed = dseed || Buffer.alloc(0);

		return utils.encode(this.pskHash(Buffer.concat([Buffer.from(path), dseed])));
	};
}

module.exports = new PskCrypto();
