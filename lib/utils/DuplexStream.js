var fs = require('fs');
var stream = require('stream');
var util = require('util');

var Duplex = stream.Duplex;

function DuplexThrough(options) {
	if (!(this instanceof DuplexThrough)) {
		return new DuplexThrough(options);
	}
	Duplex.call(this, options);
}
util.inherits(DuplexThrough, Duplex);

DuplexThrough.prototype._write = function (chunk, enc, cb) {
	this.push(chunk);
	cb();
};


DuplexThrough.prototype._read = function (n) {
	//...
};

module.exports = DuplexThrough;