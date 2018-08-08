require("../../../../engine/core");
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

	this.zipFolder = function (inputPath, outputPath) {
		zipFolderRecursively(inputPath);
		zipfile.end();
		$$.ensureFolderExists(outputPath, () => {
			zipfile.outputStream.pipe(fs.createWriteStream(path.join(outputPath, path.basename(inputPath) + ".zip"))).on("close", function () {
				console.log("done");
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

module.exports = PskArchiver;