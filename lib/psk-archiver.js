require("../../../engine/core");
const path = require("path");
const yazl = $$.requireModule("yazl");
const yauzl = $$.requireModule("yauzl");
const fs = require("fs");

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

	this.zip = function (inputPath, outputFolder, callback) {
		var ext = "";
		if(fs.lstatSync(inputPath).isDirectory()) {
			zipFolderRecursively(inputPath);
		}else{
			var filename = path.basename(inputPath)
			zipfile.addFile(inputPath, filename);
			var splitFilename = filename.split(".");
			if(splitFilename.length >= 2 ){
				ext = "." + splitFilename[splitFilename.length - 1];
			}
		}
		zipfile.end();
		$$.ensureFolderExists(outputFolder, () => {
			var destinationPath = path.join(outputFolder, path.basename(inputPath, ext) + ".zip");
			zipfile.outputStream.pipe(fs.createWriteStream(destinationPath)).on("close", function () {
				callback();
			});
		});
	};

	this.unzip = function (inputPath, outputPath) {
		yauzl.open(inputPath, {lazyEntries: true}, function (err, zipfile) {
			if (err) throw err;
			zipfile.readEntry();
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

// new PskArchiver().zip("C:\\Users\\Acer\\WebstormProjects\\privatesky\\tests\\psk-unit-testing\\zip\\input\\test", "C:\\Users\\Acer\\WebstormProjects\\privatesky\\tests\\psk-unit-testing\\zip\\input\\test\\output");
module.exports = new PskArchiver();