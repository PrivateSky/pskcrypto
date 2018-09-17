
const crypto = require('crypto');
const fs = require('fs');
const path = require("path");
const isStream = require("./isStream");
const archiver = require("../psk-archiver");
const algorithm = 'aes-256-gcm';
function encode(buffer) {
	return buffer.toString('base64')
		.replace(/\+/g, '')
		.replace(/\//g, '')
		.replace(/=+$/, '');
}
function deleteFolder(folderPath) {
	var files = fs.readdirSync(folderPath);
	files.forEach((file) => {
		var tempPath = path.join(folderPath, file);
		if(fs.statSync(tempPath).isDirectory()){
			deleteFolder(tempPath);
		}else{
			fs.unlinkSync(tempPath);
		}
	});
	fs.rmdirSync(folderPath);
}
function encryptFile(inputPath, destinationPath, password){
	if(!fs.existsSync(path.dirname(destinationPath))){
		fs.mkdirSync(path.dirname(destinationPath));
	}
	if(!fs.existsSync(destinationPath)){
		fs.writeFileSync(destinationPath,"");
	}
	var ws = fs.createWriteStream(destinationPath, {autoClose: false});
	var keySalt       = crypto.randomBytes(32);
	var key           = crypto.pbkdf2Sync(password, keySalt, 10000, 32, 'sha512');

	var aadSalt       = crypto.randomBytes(32);
	var aad           = crypto.pbkdf2Sync(password, aadSalt, 10000, 32, 'sha512');

	var salt          = Buffer.concat([keySalt, aadSalt]);
	var iv            = crypto.pbkdf2Sync(password, salt, 10000, 12, 'sha512');

	var cipher        = crypto.createCipheriv(algorithm, key, iv);
	cipher.setAAD(aad);

	archiver.zip(inputPath, cipher, function (err, cipherStream) {
		cipherStream.on("data", function (chunk) {
			ws.write(chunk)
		});
		cipherStream.on('end', function () {
			var tag = cipher.getAuthTag();
			var dataToAppend = Buffer.concat([salt, tag]);
			ws.write(dataToAppend, function (err) {
				if(err) {
					throw err;
				}
				ws.close();
				fs.lstat(inputPath, function (err, stats) {
					if(err){
						throw err;
					}
					if(stats.isDirectory()){
						console.log("delete folder");
						deleteFolder(inputPath);
					}else{
						console.log("unlink");
						fs.unlinkSync(inputPath);
					}
					console.log("End")
				})
			})
		});
	});
}

function decryptFile(encryptedInputPath, tempFolder, password, callback) {
	const stats           = fs.statSync(encryptedInputPath);
	const fileSizeInBytes = stats.size;
	const fd              = fs.openSync(encryptedInputPath, "r");
	var encryptedAuthData = Buffer.alloc(80);

	fs.readSync(fd, encryptedAuthData, 0, 80, fileSizeInBytes - 80);
	var salt       = encryptedAuthData.slice(0, 64);
	var keySalt    = salt.slice(0, 32);
	var aadSalt    = salt.slice(-32);

	var iv         = crypto.pbkdf2Sync(password, salt, 10000, 12, 'sha512');
	var key        = crypto.pbkdf2Sync(password, keySalt, 10000, 32, 'sha512');
	var aad        = crypto.pbkdf2Sync(password, aadSalt, 10000, 32, 'sha512');
	var tag        = encryptedAuthData.slice(-16);

	var decipher   = crypto.createDecipheriv(algorithm, key, iv);

	decipher.setAAD(aad);
	decipher.setAuthTag(tag);
	var rs = fs.createReadStream(encryptedInputPath, {start: 0, end: fileSizeInBytes - 81});
	if(!fs.existsSync(tempFolder)){
		fs.mkdirSync(tempFolder);
	}
	var tempArchivePath = path.join(tempFolder, path.basename(encryptedInputPath)+".zip");
	if(!fs.existsSync(tempArchivePath)){
		fs.writeFileSync(tempArchivePath);
	}
	var ws = fs.createWriteStream(tempArchivePath, {autoClose: false});
	ws.on("finish", function (err) {
		if(err){
			throw err;
		}else{
			ws.close();
			// deleteFolder(tempFolder);
			var newPath = path.join(path.normalize(encryptedInputPath+"/.."), encode(crypto.randomBytes(32)));
			// fs.renameSync(encryptedInputPath, newPath);
			// fs.unlinkSync(newPath);
			// fs.unlinkSync(tempArchivePath);
			callback(null, tempArchivePath);

		}
	});
	rs.pipe(decipher).pipe(ws);

}

function createPskHash(data){
	var hash512 = crypto.createHash('sha512');
	var hash256 = crypto.createHash('sha256');
	hash512.update(data);
	hash256.update(hash512.digest());
	return hash256.digest();
}

function isJson(data){
	try{
		JSON.parse(data);
	}catch(e){
		return false;
	}
	return true;
}

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


function deriveKey(password, iterations, dkLen) {
	iterations = iterations || 10000;
	dkLen      = dkLen || 32;
	var salt   = generateSalt(password, 32);
	var dk     = crypto.pbkdf2Sync(password, salt, iterations, dkLen, 'sha512');
	return Buffer.from(dk);
}

module.exports = {
	createPskHash,
	encrypt,
	encryptFile,
	decrypt,
	decryptFile,
	deriveKey,
	encode,
	isJson,
};


