require("../../../psknode/bundles/pskruntime");
const crypto = require("pskcrypto");
const assert = require("double-check").assert;

assert.callback("basicUidGeneratorTest", function (callback) {
	var generated = [];
	function getRandomInt(min, max) {
		return Math.floor(Math.random() * (max - min + 1)) + min;
	}
	function genUID(index) {
		if(index === 1000){
			assert.equal(generated.length, index, "Not enough uids generated");
			callback();
			return;
		}
		setTimeout(function (err) {
			var len = getRandomInt(1, 640);
			var uid = crypto.generateUid(len);
			assert.equal(uid.length, len, "Unexpected length for generated uid " + uid.len + ' - ' + len);
			generated.push(uid);
			genUID(index+1);
		},5);

	}
	genUID(0);
}, 10000);
