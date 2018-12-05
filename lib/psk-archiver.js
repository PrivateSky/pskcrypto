const path = require("path");
const yazl = require("yazl");
const yauzl = require("yauzl");
const fs = require("fs");
const DuplexStream = require("./utils/DuplexStream");
const isStream = require("./utils/isStream");
function PskArchiver() {

	function addToArchiveRecursively(zipfile, inputPath, root = '', callback) {
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
		var zipfile = new yazl.ZipFile();
		addToArchiveRecursively(zipfile, inputPath, "", function (err) {
			if(err){
				return callback(err);
			}
			zipfile.end();
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

	function zipRecursively(zipfile, obj, root, maxDepth, callback) {
		if(maxDepth !== 'undefined') {
			if (maxDepth === 0) {
				zipfile.addBuffer(new Buffer(JSON.stringify(obj)), root + "/stringify");
				return;
			}
		}
		if(typeof obj === 'number'){
			zipfile.addBuffer(new Buffer(obj.toString()), root + "/number");
		}else if(typeof obj === 'string'){
			zipfile.addBuffer(new Buffer(obj), root + "/string")
		}else if(Buffer.isBuffer(obj)){
			zipfile.addBuffer(obj, root+ "/buffer");
		}else if(isStream.isReadable(obj)){
			zipfile.addReadStream(obj, root+ "/stream");
		}else if(Array.isArray(obj)){
			for(let i=0; i<obj.length; i++){
				if(obj.length === 0){
					zipfile.addBuffer(Buffer.alloc(0), root + "/array")
				}else {
					zipRecursively(zipfile, obj[i], root + "/array/" + i, maxDepth, function (err) {
						if (err) {
							return callback(err);
						}
					});
				}
			}
		}else if(typeof obj === 'object'){
			var keys = Object.keys(obj);
			if(keys.length === 0 && obj.constructor === Object){
				zipfile.addBuffer(Buffer.alloc(0), root + "/object");
			}else{
				keys.forEach( function(key){
					var entryName;
					if(root === ""){
						entryName = key;
					}else{
						entryName = root + "/" +key;
					}
					zipRecursively(zipfile, obj[key], entryName, maxDepth-1, function (err) {
						if (err) {
							return callback(err);
						}
					});
				});
			}
		}
		callback(null);
	}
	
	this.generateObjectStructure = function(obj, structure, keyName, callback) {
		if(typeof obj === 'string'){
			structure[keyName] = {
				type: "string"
			}
		}else if(Buffer.isBuffer(obj)){
			structure[keyName] = {
				type: "buffer"
			}
		}else if(isStream.isReadable(obj)){
			structure[keyName] = {
				type: "stream"
			}
		}else {
			var subStructure = {};
			if(Array.isArray(obj)){
				structure[keyName] = {
					type: "array",
				};
				subStructure = structure[keyName];

			}else{
				if(keyName === ""){
					structure = {
						type: "object",
					};
					subStructure = structure;
				}else {
					structure[keyName] = {
						type: "object",
					};
					subStructure = structure[keyName];
				}
			}
			var keys = Object.keys(obj);
			if(keys.length > 0){
				subStructure["subKeys"] = {};
				keys.forEach( (key) => {
					this.generateObjectStructure(obj[key], subStructure["subKeys"], key, function (err) {
						if(err) {
							return callback(err);
						}
					});
				})
			}

		}
		callback(null, structure);
	};



	function addPropsRecursively(obj, splitName, type, data){
		if(splitName.length >= 1) {
			var prop = splitName.shift();
			if(splitName.length === 0){
				switch (type) {
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
				}
			}else {
				if (splitName[0] === 'array' ) {
					if (!obj.hasOwnProperty(prop)) {
						obj[prop] = [];
					}
					splitName.shift();
					addPropsRecursively(obj[prop], splitName, type, data);
				}else{
					if (!obj.hasOwnProperty(prop)) {
						obj[prop] = {};
					}
					addPropsRecursively(obj[prop], splitName, type, data);
				}
			}
		}
	}
	this.zipInMemory = function (inputObj, level, callback) {
		var zipfile = new yazl.ZipFile();
		var ds = new DuplexStream();
		zipRecursively(zipfile, inputObj, "", level, function (err) {
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

	this.unzipInMemory = function (inputZip, callback) {

		function unzipInput(zipfile){
			zipfile.readEntry();
			var obj = {};
			zipfile.once("end", function () {
				callback(null, obj);
			});

			zipfile.on("entry", function (entry) {
				zipfile.openReadStream(entry, function (err, readStream) {
					var ds = new DuplexStream();
					var str = '';
					if (err) {
						return callback(err);
					}
					readStream.on("end", function () {
						zipfile.readEntry();
					});
					ds.on("data", function (chunk) {
						str += chunk.toString();
					});

					readStream.pipe(ds).on("finish", function (err) {
						if(err){
							return callback(err);
						}
						var splitEntry = entry.fileName.split("/");
						var type = splitEntry.pop();
						addPropsRecursively(obj, splitEntry, type, new Buffer(str));
					});

				});
			})
		}
		if(Buffer.isBuffer(inputZip)){
			yauzl.fromBuffer(inputZip, {lazyEntries: true}, function (err,  zipfile) {
				if (err) {
					return callback(err);
				}
				unzipInput(zipfile)
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