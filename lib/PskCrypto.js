
const crypto = require('crypto');
const fs = require('fs');
const path = require("path");

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
	var tempFolder = path.join(process.cwd(), "tmp");

	this.encryptStream = function (inputPath, destinationFolder, password) {
		if(!fs.existsSync(tempFolder)){
			fs.mkdirSync(tempFolder);
		}
		if(!fs.existsSync(destinationFolder)){
			fs.mkdirSync(destinationFolder);
		}
		destinationFolder = destinationFolder || process.cwd();
		archiver.zip(inputPath, tempFolder, function () {
			var ext = "";
			var filename = path.basename(inputPath);
			var splitPath = filename.split(".");
			if(splitPath.length >= 2 ){
				ext = "." + splitPath[splitPath.length - 1];
			}
			var filename = path.basename(inputPath, ext);
			var destinationPath = path.join(destinationFolder, filename);
			var zipPath = path.join(tempFolder, filename + ".zip");
			utils.encryptFile(zipPath, destinationPath, password);
		});
	};

	this.decryptStream = function (encryptedInputPath, outputFolder, password) {
		utils.decryptFile(encryptedInputPath, tempFolder, password, function (err, tempArchivePath) {
			archiver.unzip(tempArchivePath, outputFolder);
		})
	};


	this.pskHash = function (data) {
		if (utils.isJson(data)) {
			return utils.createPskHash(JSON.stringify(data));
		} else {
			return utils.createPskHash(data);
		}
	};


	this.saveDSeed = function (dseed, pin, dseedPath) {
		var encryptionKey   = utils.deriveKey(pin, null, null);
		var iv              = crypto.randomBytes(16);
		var cipher          = crypto.createCipheriv('aes-256-cfb', encryptionKey, iv);
		var encryptedDSeed  = cipher.update(dseed, 'binary');
		var final           = Buffer.from(cipher.final('binary'), 'binary');
		encryptedDSeed      = Buffer.concat([iv, encryptedDSeed, final]);
		fs.writeFileSync(dseedPath, encryptedDSeed);
	};

	this.loadDseed = function (pin, dseedPath) {
		var encryptedData  = fs.readFileSync(dseedPath);
		var iv             = encryptedData.slice(0, 16);
		var encryptedDseed = encryptedData.slice(16);
		var encryptionKey  = utils.deriveKey(pin, null, null);
		var decipher       = crypto.createDecipheriv('aes-256-cfb', encryptionKey, iv);
		var dseed          = Buffer.from(decipher.update(encryptedDseed, 'binary'), 'binary');
		var final          = Buffer.from(decipher.final('binary'), 'binary');
		dseed              = Buffer.concat([dseed, final]);

		return dseed;

	};


	this.deriveSeed = function (seed, dseedLen) {
		return utils.deriveKey(seed, null, dseedLen);

	};

	this.encryptJson = function (data, dseed) {
		var cipherText = utils.encrypt(JSON.stringify(data), dseed);

		return cipherText;
	};

	this.decryptJson = function (encryptedData, dseed) {
		var plaintext = utils.decrypt(encryptedData, dseed);

		return JSON.parse(plaintext);
	};

	this.encryptBlob = function (data, dseed) {
		var ciphertext = utils.encrypt(data, dseed);

		return ciphertext;
	};

	this.decryptBlob = function (encryptedData, dseed) {
		var plaintext = utils.decrypt(encryptedData, dseed);

		return plaintext;
	};


	this.generateSeed = function (backupUrl) {
		var seed = {
			"backup": backupUrl,
			"rand"	: crypto.randomBytes(32).toString("hex")
		};
		return Buffer.from(JSON.stringify(seed));
	};
	this.generateSafeUid = function (dseed, path) {
		path = path || process.cwd();
		return utils.encode(this.pskHash(Buffer.concat([Buffer.from(path), dseed])));
	};
}

// var pcrypto = new PskCrypto();
// pcrypto.encryptStream("C:\\Users\\Acer\\WebstormProjects\\privatesky\\tests\\psk-unit-testing\\zip\\input\\test","output", "123");
// pcrypto.decryptStream("output\\test", "output2", "123");
module.exports = new PskCrypto();