
function UidGenerator() {
	const crypto = require('crypto');
	var buffer = new Array(20);
	var index = 0;


	function fillBuffer(noBytes, callback) {
		if(index === buffer.length){
			index--;
			return callback();
		}
		crypto.randomBytes(noBytes, function (err, result) {
			if(err){
				return callback(err);
			}
			buffer[index] = result;
			index++;
			fillBuffer(noBytes, callback);
		});
	}

	function shiftWithConstantLength(arr) {
		var ret = arr[0];
		for(let i=0; i<arr.length-1; i++){
			arr[i] = arr[i+1];
		}
		return ret;
	}

	this.generateUid = function (noBytes) {
		noBytes = noBytes || 32;
		if(index === 0) {
			fillBuffer(noBytes, function (err) {
				if(err) throw err;
			});
			return crypto.randomBytes(noBytes);
		}

		fillBuffer(noBytes, function (err) {
			if(err) throw err;
		});
		return shiftWithConstantLength(buffer);

	};
}

module.exports = new UidGenerator();