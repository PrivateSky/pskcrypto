const path = require("path");
const yazl = require("yazl");
const yauzl = require("yauzl");
const fs = require("fs");
const isStream = require("./utils/isStream");
const core = require("../../../engine/core");
// require("../../../builds/devel/pskruntime");
function PskArchiver() {
	let zipfile = new yazl.ZipFile();
	function zipFolderRecursively(inputPath, root = '') {
		const files = fs.readdirSync(inputPath);
		files.forEach(function (file) {
			const tempPath = path.join(inputPath, file);
			if (!fs.lstatSync(tempPath).isDirectory()) {
				zipfile.addFile(tempPath, path.join(root, file));
			} else {
				zipFolderRecursively(tempPath, path.join(root, file));
			}
		});
	}

	this.zip = function (inputPath, output, callback) {
		var ext = "";
		fs.stat(inputPath, function (err, stats) {
			if(err){
				callback(err, null);
			}else{
				if(stats.isDirectory()) {
					zipFolderRecursively(inputPath);
				}else{
					var filename = path.basename(inputPath);
					zipfile.addFile(inputPath, filename);
					var splitFilename = filename.split(".");
					if(splitFilename.length >= 2 ){
						ext = "." + splitFilename[splitFilename.length - 1];
					}
				}
				zipfile.end();
				if(isStream.isWritable(output)){
					callback(null, zipfile.outputStream.pipe(output));
				}else if(typeof output === "string") {
					$$.ensureFolderExists(output, () => {
						var destinationPath = path.join(output, path.basename(inputPath, ext) + ".zip");
						zipfile.outputStream.pipe(fs.createWriteStream(destinationPath)).on("close", function () {
							callback(null);
						});
					});
				}
			}
		})

	};

	this.unzip = function (input, outputPath, callback) {
		yauzl.open(input, {lazyEntries: true}, function (err, zipfile) {
			if (err) throw err;
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
							if (err) throw err;

							readStream.on("end", function () {
								zipfile.readEntry();
							});
							let fileName = path.join(outputPath, entry.fileName);
							let folder = path.dirname(fileName);
							$$.ensureFolderExists(folder, () => {
								let output = fs.createWriteStream(fileName);
								readStream.pipe(output);

							});
						});
					});
				}
			});
		});
	}
}

module.exports = new PskArchiver();