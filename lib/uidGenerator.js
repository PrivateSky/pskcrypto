const crypto = require('crypto');
function UidGenerator(minBuffers, buffersSize) {
	var buffers = [];
	for(var i =0 ;i < minBuffers;i++){
		generateOneBuffer(null);
	}

	function generateOneBuffer(b){
		if(!b){
			b = new Buffer(0);
		}
		const sz = buffersSize - b.length;
		crypto.randomBytes(sz, function (err, res) {
			buffers.push(Buffer.concat([res, b]));
		});
	}

	function extractN(n){
		var sz = Math.floor(n / buffersSize);
		var ret = [];
		if(buffers.length === 0){
			buffersSize *= 2;
			console.log("buffersEmpty");
		}
		for(var i=0; i<sz; i++){
			ret.push(buffers.shift());
			generateOneBuffer(null);
		}

		var remainder = n % buffersSize;
		if(remainder > 0){
			var front = buffers.shift();
			ret.push(front.slice(0,remainder));
			generateOneBuffer(front.slice(remainder));
		}
		return Buffer.concat(ret);
	}

	this.getNbytes = function(n){
		var totalSize = buffers.length * buffersSize;
		if(n < totalSize){
			return extractN(n)
		}	  else {
			return crypto.randomBytes(n);
		}
	}
}

module.exports.createUidGenerator = function (minBuffers, bufferSize) {
	return new UidGenerator(minBuffers, bufferSize);
};
