const stream = require('stream');
const util = require('util');

const PassThrough = stream.PassThrough;

function PassThroughStream(options) {
    if (!(this instanceof PassThroughStream)) {
        return new PassThroughStream(options);
    }
    PassThrough.call(this, options);

    let size = 0;

    this.addToSize = function (amount) {
        size += amount;
    };

    this.getSize = function () {
        return size;
    }
}

util.inherits(PassThroughStream, PassThrough);

PassThroughStream.prototype._write = function (chunk, enc, cb) {
    this.addToSize(chunk.length);
    this.push(chunk);
    cb();
};


PassThroughStream.prototype._read = function (n) {

};

module.exports = PassThroughStream;