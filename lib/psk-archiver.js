const path = require("path");
const yazl = require("yazl");
const yauzl = require("yauzl");
const fs = require("fs");
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
					console.log(entry.filename);
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

	function zipObjectRecursively(obj,root = "",  callback){
		console.log("zipObjectRecursively")
		var keys = Object.keys(obj);
		keys.forEach( (key) => {
			if(typeof obj[key] === "string"){
				zipfile.addBuffer(new Buffer(obj[key]), key);
			}else if(Buffer.isBuffer(obj[key])){
				zipfile.addBuffer(obj[key], key);
			}else if(isStream.isReadable(obj[key])){
				zipfile.addReadStream(obj[key], key);
			}else {
				zipObjectRecursively(obj[key], root+"/"+key, function () {
				});
			}
		});
		callback();
	}

	this.zipInMemory = function (inputObj, output, callback) {
		zipObjectRecursively(inputObj, "", function () {
			zipfile.end();
			if (isStream.isWritable(output)) {
				callback(null, zipfile.outputStream.pipe(output));
			} else {
				if (typeof output === "string") {
					$$.ensureFolderExists(output, () => {
						var destinationPath = path.join(output, path.basename(output) + ".zip");
						zipfile.outputStream.pipe(fs.createWriteStream(destinationPath)).on("close", function () {
							callback(null);
						});
					});
				}
			}
		})
	};
	
	this.unzipInMemory = function (input, output, callback) {
		yauzl.fromBuffer(input, {lazyEntries: true}, function (err, zipFile) {
			if (err) {
				return callback(err);
			}
			zipFile.readEntry();
			zipfile.once("end", function () {
				callback();
			});
			zipFile.on("entry", function (entry) {
				zipFile.openReadStream(entry, function (err, readStream) {
					if (err) {
						return callback(err);
					}
					readStream.on("end", function () {
						zipFile.readEntry();
					});
					readStream.pipe(output);
				});
			})
		});
	}
}



module.exports = new PskArchiver();