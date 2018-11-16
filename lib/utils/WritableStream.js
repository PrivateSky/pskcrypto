// const { Writable } = require('stream');
const stream = require("stream");
const Writable = stream.Writable;
const util = require('util');
const isStream = require("./isStream")
function WritableStream() {
	Writable.call(this);
	var buffer = Buffer.alloc(0);

	this._write = function (chunk, encoding, callback) {
		if(!Buffer.isBuffer(chunk)){
			chunk = Buffer.from(chunk, encoding);
		}
		buffer = Buffer.concat([buffer, chunk]);
		callback();
	};

	this.getData = function(){
		return buffer;
	};
}
util.inherits(WritableStream, Writable);

module.exports = WritableStream;