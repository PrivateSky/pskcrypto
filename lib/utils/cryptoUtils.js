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

function deleteRecursively(inputPath, callback){

	fs.stat(inputPath, function(err, stats) {
		if(err){
			callback(err,stats);
			return;
		}
		if(stats.isFile()){
			fs.unlink(inputPath, function(err) {
				if(err) {
					callback(err,null);
				}else{
					callback(null,true);
				}
			});
		}else if(stats.isDirectory()){
			fs.readdir(inputPath, function(err, files) {
				if(err){
					callback(err,null);
					return;
				}
				var f_length = files.length;
				var f_delete_index = 0;

				var checkStatus = function(){
					if(f_length === f_delete_index){
						fs.rmdir(inputPath, function(err) {
							if(err){
								callback(err,null);
							}else{
								callback(null,true);
							}
						});
						return true;
					}
					return false;
				};
				if(!checkStatus()){
					files.forEach(function (file) {
						var tempPath = path.join(inputPath, file);
						deleteRecursively(tempPath,function removeRecursiveCB(err, status){
							if(!err){
								f_delete_index ++;
								checkStatus();
							}else{
								callback(err,null);
							}
						});
					});
				}
			});
		}
	});
}

function encryptFile(inputPath, destinationPath, password, callback){
    fs.open(destinationPath, "wx", function (err, fd) {
        if(err){
        	callback(err);
        	return;
		}

        fs.close(fd, function (err) {
        	if(err){
        		return callback(err);
			}

            var ws = fs.createWriteStream(destinationPath, {autoClose: false});
            var keySalt       = crypto.randomBytes(32);
            var key           = crypto.pbkdf2Sync(password, keySalt, iterations_number, 32, 'sha512');

            var aadSalt       = crypto.randomBytes(32);
            var aad           = crypto.pbkdf2Sync(password, aadSalt, iterations_number, 32, 'sha512');

            var salt          = Buffer.concat([keySalt, aadSalt]);
            var iv            = crypto.pbkdf2Sync(password, salt, iterations_number, 12, 'sha512');

            var cipher        = crypto.createCipheriv(algorithm, key, iv);
            cipher.setAAD(aad);
            archiver.zipStream(inputPath, cipher, function (err, cipherStream) {

            	if(err){
            		return callback(err);
				}

                cipherStream.on("data", function (chunk) {
                    ws.write(chunk);
                });
                cipherStream.on('end', function () {
                    var tag = cipher.getAuthTag();
                    var dataToAppend = Buffer.concat([salt, tag]);
                    ws.end(dataToAppend, function (err) {
                        if(err) {
                            return callback(err);
                        }
                        deleteRecursively(inputPath, function (err, status) {
                            if(err){
                                callback(err, null);
                            }else{
                                callback(null, status);
                            }
                        })
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
					var encryptedAuthData = Buffer.alloc(80);

					fs.read(fd, encryptedAuthData, 0, 80, fileSizeInBytes - 80, function (err, bytesRead) {
						var salt = encryptedAuthData.slice(0, 64);
						var keySalt = salt.slice(0, 32);
						var aadSalt = salt.slice(-32);

						var iv = crypto.pbkdf2Sync(password, salt, iterations_number, 12, 'sha512');
						var key = crypto.pbkdf2Sync(password, keySalt, iterations_number, 32, 'sha512');
						var aad = crypto.pbkdf2Sync(password, aadSalt, iterations_number, 32, 'sha512');
						var tag = encryptedAuthData.slice(-16);

						var decipher = crypto.createDecipheriv(algorithm, key, iv);

						decipher.setAAD(aad);
						decipher.setAuthTag(tag);
						var rs = fs.createReadStream(encryptedInputPath, {start: 0, end: fileSizeInBytes - 81});
						$$.ensureFolderExists(tempFolder, function (err) {
							if (!err) {
								var tempArchivePath = path.join(tempFolder, path.basename(encryptedInputPath) + ".zip");

                                fs.open(tempArchivePath, "wx", function (err, fd) {
                                    if(err){
                                        callback(err);
                                        return;
                                    }

                                    fs.close(fd, function (err) {

                                        if(!err){
                                            var ws = fs.createWriteStream(tempArchivePath, {autoClose: false});
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
	var key           = crypto.pbkdf2Sync(password, keySalt, iterations_number, 32, 'sha512');

	var aadSalt       = crypto.randomBytes(32);
	var aad           = crypto.pbkdf2Sync(password, aadSalt, iterations_number, 32, 'sha512');

	var salt          = Buffer.concat([keySalt, aadSalt]);
	var iv            = crypto.pbkdf2Sync(password, salt, iterations_number, 12, 'sha512');

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

	var iv         = crypto.pbkdf2Sync(password, salt, iterations_number, 12, 'sha512');
	var key        = crypto.pbkdf2Sync(password, keySalt, iterations_number, 32, 'sha512');
	var aad        = crypto.pbkdf2Sync(password, aadSalt, iterations_number, 32, 'sha512');

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

function encryptObjectInMemory(inputObj, password, depth, callback){
	archiver.zipInMemory(inputObj, depth, function (err, zippedObj) {
		if(err){
			return callback(err);
		}
		var cipherText = encrypt(zippedObj, password);
		callback(null, cipherText);
	})
}

function decryptObjectInMemory(encryptedObject, password, callback){
	var zippedObject = decrypt(encryptedObject, password);
	archiver.unzipInMemory(zippedObject, function (err, obj) {
		if(err){
			return callback(err);
		}
		callback(null, obj);
	})
}

function deriveKey(password, iterations, dkLen) {
	iterations = iterations || 1000;
	dkLen      = dkLen || 32;
	var salt   = generateSalt(password, 32);
	var dk     = crypto.pbkdf2Sync(password, salt, iterations, dkLen, 'sha512');
	return Buffer.from(dk);
}

module.exports = {
	createPskHash,
	encrypt,
	encryptFile,
	encryptObjectInMemory,
	decrypt,
	decryptFile,
	decryptObjectInMemory,
	deriveKey,
	deleteRecursively,
	encode,
	isJson
};

