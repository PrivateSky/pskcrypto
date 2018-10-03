
function UidGenerator() {
	const crypto = require('crypto');
	var buffer = new Array(20);
	var index = 0;


	function fillBuffer(callback) {
		if(index === buffer.length){
			index--;
			return callback();
		}
		crypto.randomBytes(32, function (err, result) {
			if(err){
				return callback(err);
			}
			buffer[index] = encode(result);
			index++;
			fillBuffer(callback);
		});
	}

	function shiftWithConstantLength(arr) {
		var ret = arr[0];
		for(let i=0; i<arr.length-1; i++){
			arr[i] = arr[i+1];
		}
		return ret;
	}

	this.generateUid = function () {
		// console.log("----Buffer----", buffer);
		if(index === 0) {
			console.log("index===0");
			fillBuffer(function (err) {
				if(err) throw err;
			});
			return encode(crypto.randomBytes(32));
		}
		console.log("index!=0", index);
		fillBuffer(function (err) {
			if(err) throw err;
		});
		return shiftWithConstantLength(buffer);

	};
}

var gen = new UidGenerator();

for(var i=0; i<10000; i++){
	(function next(index) {
		setTimeout(function (err) {
			console.log(gen.generateUid());
		},index+1);
	})(i);
}
