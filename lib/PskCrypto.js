const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

const utils = require("./utils/cryptoUtils");

const PassThroughStream = require('./utils/PassThroughStream');

const tempFolder = os.tmpdir();

function PskCrypto() {

    /*--------------------------------------------- ECDSA functions ------------------------------------------*/

    this.sign = function (privateKey, digest) {
        if (typeof digest === "string") {
            digest = Buffer.from(digest, "hex");
        }

        return crypto.createSign("sha256").update(digest).sign(privateKey);
    };

    this.verify = function (publicKey, signature, digest) {
        if (typeof digest === "string") {
            digest = Buffer.from(digest, "hex");
        }

        if (typeof signature === "string") {
            signature = Buffer.from(signature, "hex");
        }
        return crypto.createVerify("sha256").update(digest).verify(publicKey, signature);
    };

    this.generateKeyPair = (callback) => {
        crypto.generateKeyPair('rsa', {
            modulusLength: 4096,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem',
            }
        }, callback);
    };

    this.privateEncrypt = (privateKey, data) => {
        if (typeof data === "string") {
            data = Buffer.from(data);
        }

        return crypto.privateEncrypt(privateKey, data);
    };

    this.privateDecrypt = (privateKey, encryptedData) => {
        if (typeof encryptedData === "string") {
            encryptedData = Buffer.from(encryptedData);
        }

        return crypto.privateDecrypt(privateKey, encryptedData);
    };

    this.publicEncrypt = (publicKey, data) => {
        if (typeof data === "string") {
            data = Buffer.from(data);
        }

        return crypto.publicEncrypt(publicKey, data);
    };

    this.publicDecrypt = (publicKey, encryptedData) => {
        if (typeof encryptedData === "string") {
            encryptedData = Buffer.from(encryptedData);
        }

        return crypto.publicDecrypt(publicKey, encryptedData);
    };

    /*---------------------------------------------Encryption functions -------------------------------------*/

    this.encryptStream = function (inputPath, destinationPath, password, callback) {
        const PskArchiver = require("./psk-archiver");
        const archiver = new PskArchiver();

        archiver.on('progress', (progress) => {
            self.emit('progress', progress);
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
        const PskArchiver = require("./psk-archiver");
        const archiver = new PskArchiver();

        decryptFile(encryptedInputPath, tempFolder, password, function (err, tempArchivePath) {
            if (err) {
                return callback(err);
            }

            archiver.on('progress', (progress) => {
                self.emit('progress', 10 + 0.9 * progress);
            });


            archiver.unzipStream(tempArchivePath, outputFolder, function (err, unzippedFileNames) {
                if (err) {
                    return callback(err);
                }

                utils.deleteRecursively(tempArchivePath, function (err) {
                    if (err) {
                        return callback(err);
                    }

                    callback(undefined, unzippedFileNames);
                });

            });
        })
    };

    this.encryptObject = function (inputObj, dseed, depth, callback) {
        const PskArchiver = require("./psk-archiver");
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
        const PskArchiver = require("./psk-archiver");
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
        encryptedDSeed = Buffer.concat([iv, encryptedDSeed, final]);
        fs.writeFile(path, encryptedDSeed, function (err) {
            callback(err);
        });
    };


    this.loadData = function (password, path, callback) {

        fs.readFile(path, null, (err, encryptedData) => {
            if (err) {
                callback(err);
            } else {
                const iv = encryptedData.slice(0, 16);
                const encryptedDseed = encryptedData.slice(16);
                const encryptionKey = this.deriveKey(password, null, null);
                const decipher = crypto.createDecipheriv('aes-256-cfb', encryptionKey, iv);
                let dseed = Buffer.from(decipher.update(encryptedDseed, 'binary'), 'binary');
                const final = Buffer.from(decipher.final('binary'), 'binary');
                dseed = Buffer.concat([dseed, final]);
                callback(null, dseed);
            }
        });
    };


    this.generateSafeUid = function (password, additionalData) {
        password = password || Buffer.alloc(0);
        if (!additionalData) {
            additionalData = Buffer.alloc(0);
        }

        if (!Buffer.isBuffer(additionalData)) {
            additionalData = Buffer.from(additionalData);
        }

        return utils.encode(this.pskHash(Buffer.concat([password, additionalData])));
    };

    this.deriveKey = function deriveKey(password, iterations, dkLen) {
        iterations = iterations || 1000;
        dkLen = dkLen || 32;
        const salt = utils.generateSalt(password, 32);
        const dk = crypto.pbkdf2Sync(password, salt, iterations, dkLen, 'sha512');
        return Buffer.from(dk);
    };

    this.randomBytes = crypto.randomBytes;
    this.PskHash = utils.PskHash;

    //-------------------------- Internal functions -----------------------------------
    function decryptFile(encryptedInputPath, tempFolder, password, callback) {
        fs.stat(encryptedInputPath, function (err, stats) {
            if (err) {
                return callback(err, null);
            }

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

                        const iv = crypto.pbkdf2Sync(password, salt, utils.iterations_number, 12, 'sha512');
                        const key = crypto.pbkdf2Sync(password, keySalt, utils.iterations_number, 32, 'sha512');
                        const aad = crypto.pbkdf2Sync(password, aadSalt, utils.iterations_number, 32, 'sha512');
                        const tag = encryptedAuthData.slice(-16);

                        const decipher = crypto.createDecipheriv(utils.algorithm, key, iv);

                        decipher.setAAD(aad);
                        decipher.setAuthTag(tag);
                        const rs = fs.createReadStream(encryptedInputPath, {start: 0, end: fileSizeInBytes - 81});
                        fs.mkdir(tempFolder, {recursive: true}, function (err) {

                            if (err) {
                                return callback(err);
                            }
                            const tempArchivePath = path.join(tempFolder, path.basename(encryptedInputPath) + ".zip");

                            fs.open(tempArchivePath, "w", function (err, fd) {
                                if (err) {
                                    callback(err);
                                    return;
                                }

                                fs.close(fd, function (err) {

                                    if (err) {
                                        return callback(err);
                                    }

                                    const ptStream = new PassThroughStream();

                                    const ws = fs.createWriteStream(tempArchivePath, {autoClose: false});
                                    ws.on("finish", function () {
                                        callback(null, tempArchivePath);
                                    });


                                    let progressLength = 0;
                                    let totalLength = 0;

                                    /**
                                     * TODO review this
                                     * In browser, piping will block the event loop and the stack queue is not called.
                                     */
                                    rs.on("data", (chunk) => {
                                        progressLength += chunk.length;
                                        totalLength += chunk.length;

                                        if (progressLength > 300000) {
                                            progressLength = 0;
                                            emitProgress(fileSizeInBytes, totalLength)
                                        }
                                    });

                                    rs.pipe(decipher).pipe(ptStream).pipe(ws);

                                });
                            });
                        });

                    });

                }
            });
        });
    }

    function emitProgress(total, processed) {


        if (processed > total) {
            processed = total;
        }

        const progress = (100 * processed) / total;
        self.emit('progress', parseInt(progress));
    }

}

module.exports = new PskCrypto();
