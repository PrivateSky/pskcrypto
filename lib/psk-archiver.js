const path = require("path");
const yazl = require("yazl");
const yauzl = require("yauzl");
const fs = require("fs");
const DuplexStream = require("./utils/DuplexStream");
const PassThroughStream = require("./utils/PassThroughStream");
const isStream = require("./utils/isStream");

const EventEmitter = require('events');

const countFiles = require('./utils/countFiles');

function PskArchiver() {

    const self = this;

    const event = new EventEmitter();

    this.on = event.on;
    this.off = event.off;
    this.emit = event.emit;

    this.zipStream = function (inputPath, output, callback) {
        let ext = "";
        const zipFile = new yazl.ZipFile();
        const ptStream = new PassThroughStream();

        countFiles.computeSize(inputPath, (err, totalSize) => {
            if (err) {
                return callback(err);
            }

            __addToArchiveRecursively(zipFile, inputPath, "", (err) => {
                if (err) {
                    return callback(err);
                }

                zipFile.end();
                const filename = path.basename(inputPath);
                const splitFilename = filename.split(".");
                if (splitFilename.length >= 2) {
                    ext = "." + splitFilename[splitFilename.length - 1];
                }
                const myStream = zipFile.outputStream.pipe(ptStream);

                let progressLength = 0;
                let totalLength = 0;

                /**
                 * TODO review this
                 * In browser, piping will block the event loop and the stack queue is not called.
                 */
                myStream.on("data", (chunk) => {
                    progressLength += chunk.length;
                    totalLength += chunk.length;

                    if (progressLength > 300000) {
                        myStream.pause();
                        progressLength = 0;
                        setTimeout(function () {
                            myStream.resume();
                        }, 10);
                        emitProgress(totalSize, totalLength)
                    }
                });

                myStream.on('end', () => {
                    emitProgress(totalSize, totalSize);
                    emitTotalSize(totalSize);
                });
                if (isStream.isWritable(output)) {
                    callback(null, myStream.pipe(output));
                } else if (typeof output === "string") {
                    $$.ensureFolderExists(output, () => {
                        const destinationPath = path.join(output, path.basename(inputPath, ext) + ".zip");
                        myStream.pipe(fs.createWriteStream(destinationPath));
                    });
                }
            });

            function __addToArchiveRecursively(zipFile, inputPath, root = '', callback) {
                root = root || '';
                fs.stat(inputPath, (err, stats) => {
                    if (err) {
                        return callback(err);
                    }
                    if (stats.isFile()) {
                        zipFile.addFile(inputPath, path.join(root, path.basename(inputPath)));
                        callback(null);

                    } else {
                        fs.readdir(inputPath, (err, files) => {
                            if (err) {
                                return callback(err);
                            }
                            const f_length = files.length;
                            let f_add_index = 0;

                            const checkStatus = () => {
                                if (f_length === f_add_index) {
                                    callback(null);
                                    return true;
                                }
                                return false;
                            };

                            if (!checkStatus()) {
                                files.forEach(file => {
                                    const tempPath = path.join(inputPath, file);
                                    __addToArchiveRecursively(zipFile, tempPath, path.join(root, path.basename(inputPath)), (err) => {
                                        if (err) {
                                            return callback(err);
                                        }
                                        f_add_index++;
                                        checkStatus();
                                    })
                                });
                            }
                        })
                    }
                });
            }

        });

    };

    this.unzipStream = function (input, outputPath, callback) {

        let size = 0;

        fs.stat(input, (err, stats) => {
            if (err) {
                return callback(err);
            }

            let totalSize = stats.size;

            const refreshIntervalId = setInterval(() => {
                emitProgress(totalSize, size);
            }, 50);

            yauzl.open(input, {lazyEntries: true}, (err, zipFile) => {
                if (err) {
                    return callback(err);
                }

                const fileNames = [];
                zipFile.readEntry();
                zipFile.once("end", () => {
                    emitProgress(totalSize, totalSize);
                    console.log("END");
                    clearInterval(refreshIntervalId);
                    callback(null, fileNames);
                });
                zipFile.on("entry", (entry) => {
                    if (entry.fileName.endsWith(path.sep)) {
                        zipFile.readEntry();
                    } else {
                        let folder = path.dirname(entry.fileName);
                        $$.ensureFolderExists(path.join(outputPath, folder), () => {
                            zipFile.openReadStream(entry, (err, readStream) => {
                                if (err) {
                                    return callback(err);
                                }
                                readStream.on("end", () => {
                                    zipFile.readEntry();
                                });
                                const ptStream = new PassThroughStream();
                                let fileName = path.join(outputPath, entry.fileName);
                                let folder = path.dirname(fileName);
                                const tempStream = readStream.pipe(ptStream);

                                $$.ensureFolderExists(folder, (err) => {
                                    if (err) {
                                        return callback(err);
                                    }

                                    size += ptStream.getSize();
                                    let output = fs.createWriteStream(fileName);
                                    fileNames.push(fileName);
                                    tempStream.pipe(output);
                                });
                            });
                        });
                    }
                });
            });

        });

    };

    this.zipInMemory = function (inputObj, depth, callback) {
        const zipFile = new yazl.ZipFile();
        const ds = new DuplexStream();
        zipRecursively(zipFile, inputObj, "", depth, (err) => {
            if (err) {
                return callback(err);
            }
            zipFile.end();
            let buffer = Buffer.alloc(0);
            ds.on('data', (chunk) => {
                buffer = Buffer.concat([buffer, chunk]);
            });

            zipFile.outputStream.pipe(ds).on("finish", (err) => {
                if (err) {
                    return callback(err);
                }
                callback(null, buffer);
            });
        })
    };

    this.unzipInMemory = function (inputZip, callback) {

        function unzipInput(zipFile) {
            zipFile.readEntry();
            const obj = {};
            zipFile.once("end", () => {
                callback(null, obj);
            });

            zipFile.on("entry", (entry) => {
                zipFile.openReadStream(entry, (err, readStream) => {
                    const ds = new DuplexStream();
                    let str = '';
                    if (err) {
                        return callback(err);
                    }
                    readStream.on("end", () => {
                        zipFile.readEntry();
                    });
                    ds.on("data", (chunk) => {
                        str += chunk.toString();
                    });

                    readStream.pipe(ds).on("finish", (err) => {
                        if (err) {
                            return callback(err);
                        }
                        const splitEntry = entry.fileName.split("/");
                        const type = splitEntry.pop();
                        addPropsRecursively(obj, splitEntry, type, new Buffer(str));
                    });

                });
            })
        }

        if (Buffer.isBuffer(inputZip)) {
            yauzl.fromBuffer(inputZip, {lazyEntries: true}, (err, zipFile) => {
                if (err) {
                    return callback(err);
                }
                unzipInput(zipFile)
            });
        } else {
            return callback(new Error("input should be a buffer"));
        }

    };

    function zipRecursively(zipFile, obj, root, depth, callback) {
        if (depth === 0) {
            zipFile.addBuffer(new Buffer(JSON.stringify(obj)), root + "/stringify");
            return;
        }

        if (typeof obj === 'undefined') {
            zipFile.addBuffer(Buffer.alloc(0), root + "/undefined");
        } else if (typeof obj === 'number') {
            zipFile.addBuffer(new Buffer(obj.toString()), root + "/number");
        } else if (typeof obj === 'string') {
            zipFile.addBuffer(new Buffer(obj), root + "/string")
        } else if (obj === null) {
            zipFile.addBuffer(Buffer.alloc(0), root + "/null");
        } else if (Buffer.isBuffer(obj)) {
            zipFile.addBuffer(obj, root + "/buffer");
        } else if (isStream.isReadable(obj)) {
            zipFile.addReadStream(obj, root + "/stream");
        } else if (Array.isArray(obj)) {
            for (let i = 0; i < obj.length; i++) {
                if (obj.length === 0) {
                    zipFile.addBuffer(Buffer.alloc(0), root + "/array")
                } else {
                    zipRecursively(zipFile, obj[i], root + "/array/" + i, depth, (err) => {
                        if (err) {
                            return callback(err);
                        }
                    });
                }
            }
        } else if (obj && typeof obj === 'object') {
            let keys = Object.keys(obj);
            if (keys.length === 0 && obj.constructor === Object) {
                zipFile.addBuffer(Buffer.alloc(0), root + "/object");
            } else {
                const encodedObj = {};
                Object.entries(obj).forEach(([key, value]) => {
                    encodedObj[encodeURIComponent(key)] = value;
                });
                obj = encodedObj;
                keys = Object.keys(obj);
                keys.forEach(key => {
                    let entryName;
                    if (root === "") {
                        entryName = key;
                    } else {
                        entryName = root + "/" + key;
                    }
                    zipRecursively(zipFile, obj[key], entryName, depth - 1, (err) => {
                        if (err) {
                            return callback(err);
                        }
                    });
                });
            }
        } else {
            throw new Error('Should never reach this');
        }
        callback(null);
    }

    function addPropsRecursively(obj, splitName, type, data) {
        if (splitName.length >= 1) {
            const prop = decodeURIComponent(splitName.shift());

            if (splitName.length === 0) {
                switch (type) {
                    case 'undefined':
                        obj[prop] = undefined;
                        break;
                    case 'null':
                        obj[prop] = null;
                        break;
                    case 'number':
                        obj[prop] = parseInt(data.toString());
                        break;
                    case 'string':
                        obj[prop] = data.toString();
                        break;
                    case 'stream':
                        obj[prop] = bufferToStream(data);
                        break;
                    case 'array':
                        obj[prop] = [];
                        break;
                    case 'object':
                        obj[prop] = {};
                        break;
                    case 'stringify':
                        obj[prop] = JSON.parse(data.toString());
                        break;
                    default:
                        throw new Error('Should never reach this');
                }
            } else {
                if (splitName[0] === 'array') {
                    if (!obj.hasOwnProperty(prop)) {
                        obj[prop] = [];
                    }
                    splitName.shift();
                    addPropsRecursively(obj[prop], splitName, type, data);
                } else {
                    if (!obj.hasOwnProperty(prop)) {
                        obj[prop] = {};
                    }
                    addPropsRecursively(obj[prop], splitName, type, data);
                }
            }
        }
    }


    function bufferToStream(buffer) {
        let stream = new require('stream').Readable();
        stream.push(buffer);
        stream.push(null);
        return stream;
    }

    function emitProgress(total, processed) {


        if (processed > total) {
            processed = total;
        }

        const progress = (100 * processed) / total;
        self.emit('progress', progress);
    }

    function emitTotalSize(total) {
        self.emit('total', total);
    }


}

module.exports = PskArchiver;