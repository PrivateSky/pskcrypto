require("../../../psknode/bundles/pskruntime");
const psk_crypto = require("pskcrypto");
const assert = require("double-check").assert;


psk_crypto.uidGenerator.registerObserver(function(err, stats){
	console.log("Received: ", stats);
});

var crypto = require("crypto");

var counter = 0;

function FakeGenerator(){
	var counter = 0;

	this.generate = function (size) {
		var arr = [];
		for(let i=0; i<size; i++){
			arr.push(counter++);
		}
		return $$.Buffer.from(arr);
	}

}
var fg = new FakeGenerator();
var fg2 = new FakeGenerator();
var arr = [];

var sizes = [128, 100, 87, 32];

for(let i=0; i<10000; i++){
	arr.push(i);
}
var buff = $$.Buffer.from(arr);
/*crypto.randomBytes = function (size, callback) {
	if(!callback){
		return fg.generate(size);
	}
	callback(null, fg.generate(size));
};*/
function getRandomInt(min, max) {
	return Math.floor(Math.random() * (max - min + 1)) + min;
}
var prevSize = 0;
var totalLength = 0;



for(var i=0;i<2500;i++) {
	var size = 128;
	totalLength+=size;
	//console.log(buff.slice(prevSize, prevSize+size));
	setTimeout(function(){
		psk_crypto.generateUid(size);
	}, i);

	//console.log("prevSize =", prevSize, "size =", size);
	prevSize = prevSize + size;
}