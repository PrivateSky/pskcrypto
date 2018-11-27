const path = require("path");
const yazl = require("yazl");
const yauzl = require("yauzl");
const fs = require("fs");
const DuplexStream = require("./utils/DuplexStream");
const isStream = require("./utils/isStream");
require("../../../engine/core");
require("callflow");
function PskArchiver() {
	let zipfile = new yazl.ZipFile();

	function addToArchiveRecursively(inputPath, root = '', callback) {
		root = root || '';
		fs.stat(inputPath, function (err, stats) {
			if (err) {
				return callback(err);
			}
			if (stats.isFile()) {
				zipfile.addFile(inputPath, path.join(root, path.basename(inputPath)));
				callback(null);
			} else {
				fs.readdir(inputPath, function (err, files) {
					if (err) {
						return callback(err);
					}
					var f_length = files.length;
					var f_add_index = 0;

					var checkStatus = function () {
						if (f_length === f_add_index) {
							callback(null);
							return true;
						}
						return false;
					};

					if (!checkStatus()) {
						files.forEach(function (file) {
							var tempPath = path.join(inputPath, file);
							addToArchiveRecursively(tempPath, path.join(root, file), function (err) {
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

	this.zipStream = function (inputPath, output, callback) {
		var ext = "";
		addToArchiveRecursively(inputPath, "", function (err) {
			if(err){
				return callback(err);
			}
			var filename = path.basename(inputPath);
			var splitFilename = filename.split(".");
			if (splitFilename.length >= 2) {
				ext = "." + splitFilename[splitFilename.length - 1];
			}
			if (isStream.isWritable(output)) {
				callback(null, zipfile.outputStream.pipe(output));
			} else if (typeof output === "string") {
				$$.ensureFolderExists(output, () => {
					var destinationPath = path.join(output, path.basename(inputPath, ext) + ".zip");
					zipfile.outputStream.pipe(fs.createWriteStream(destinationPath)).on("close", function () {
						callback(null);
					});
				});
			}
		});
	};

	this.unzipStream = function (input, outputPath, callback) {
		yauzl.open(input, {lazyEntries: true}, function (err, zipfile) {
			if (err) {
				return callback(err);
			}
			zipfile.readEntry();
			zipfile.once("end", function () {
				callback();
			});
			zipfile.on("entry", function (entry) {
				if (entry.fileName.endsWith(path.sep)) {
					zipfile.readEntry();
				} else {
					let folder = path.dirname(entry.fileName);
					$$.ensureFolderExists(path.join(outputPath, folder), () => {
						zipfile.openReadStream(entry, function (err, readStream) {
							if (err) {
								return callback(err);
							}
							readStream.on("end", function () {
								zipfile.readEntry();
							});
							let fileName = path.join(outputPath, entry.fileName);
							let folder = path.dirname(fileName);
							$$.ensureFolderExists(folder, (err) => {
								if (err) {
									return callback(err);
								}
								let output = fs.createWriteStream(fileName);
								readStream.pipe(output);
							});
						});
					});
				}
			});
		});
	};

	function zipObjectRecursively(obj, root, callback){
		var keys = Object.keys(obj);
		keys.forEach( (key) => {
			var entryName = "";
			if(root === ""){
				entryName = key;
			}else{
				entryName = root + "/" + key;
			}
			if(typeof obj[key] === "string"){
				zipfile.addBuffer(new Buffer(obj[key]), entryName + "/string");
			}else if(Buffer.isBuffer(obj[key])){
				zipfile.addBuffer(obj[key], entryName + "/buffer");
			}else if(isStream.isReadable(obj[key])){
				zipfile.addReadStream(obj[key], entryName + "/stream");
			}else if(typeof obj[key] === 'object'){
				zipObjectRecursively(obj[key], entryName, function (err) {
					if(err){
						return callback(err);
					}
				});
			}
			else{
				return callback(new Error("Invalid type " + typeof obj[key] + " for zipping member " + key));
			}
		});
		callback(null);
	}

	this.zipInMemory = function (inputObj, callback) {
		var ds = new DuplexStream();
		zipObjectRecursively(inputObj, "", function (err) {
			if(err){
				return callback(err);
			}
			zipfile.end();
			var buffer = Buffer.alloc(0);
			ds.on('data', function (chunk) {
				buffer = Buffer.concat([buffer, chunk]);
			});

			zipfile.outputStream.pipe(ds).on("finish", function (err) {
				if(err){
					return callback(err);
				}
				callback(null, buffer);
			});
		})
	};

	function addNestedProp(obj, splitName, type, data) {
		if(splitName.length >= 1) {
			var prop = splitName.shift();
			if (splitName.length === 0) {
				if(type === 'string'){
					obj[prop] = data.toString();
				}else if(type === 'stream') {
					obj[prop] = bufferToStream(data);
				}else{
					obj[prop] = data;
				}

			} else {
				if(!obj.hasOwnProperty(prop)) {
					obj[prop] = {};
				}
				addNestedProp(obj[prop], splitName, type, data);
			}
		}
	}

	this.unzipInMemory = function (inputZip, callback) {
		function unzipInput(zipFile){
			zipFile.readEntry();
			var obj = {};
			zipFile.once("end", function () {
				callback(null, obj);
			});


			zipFile.on("entry", function (entry) {
				zipFile.openReadStream(entry, function (err, readStream) {
					var ds = new DuplexStream();
					var arr = [];
					if (err) {
						return callback(err);
					}
					readStream.on("end", function () {
						zipFile.readEntry();
					});
					ds.on("data", function (chunk) {
						arr.push(chunk);
					});

					readStream.pipe(ds).on("finish", function (err) {
						if(err){
							return callback(err);
						}
						var splitEntry = entry.fileName.split("/");
						var type = splitEntry.pop();
						addNestedProp(obj, splitEntry, type, new Buffer(arr));
					});

				});
			})
		}
		if(Buffer.isBuffer(inputZip)){
			yauzl.fromBuffer(inputZip, {lazyEntries: true}, function (err, zipFile) {
				if (err) {
					return callback(err);
				}
				unzipInput(zipFile)
			});
		}else {
			return callback(new Error("input should be a buffer"));
		}

	};

	function bufferToStream(buffer) {
		let stream = new require('stream').Readable();
		stream.push(buffer);
		stream.push(null);
		return stream;
	}
}



module.exports = new PskArchiver();