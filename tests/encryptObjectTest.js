require("../../../psknode/bundles/pskruntime");
const path = require("path");
const fs = require("fs");
var crypto = require("pskcrypto");
var assert = require("double-check").assert;

function objectsAreEqual(obj1, obj2, callback) {
    if(!obj1 && !obj2){
        return true;
    }
    var keys = Object.keys(obj1);
    for(let i=0; i < keys.length; i++){
        if(!obj2.hasOwnProperty(keys[i])){
            return false;
        }
        if(typeof obj1[keys[i]] !== typeof obj2[keys[i]]){
            return callback(null, false);
        }
        if(crypto.isStream.isReadable(obj1[keys[i]]) && crypto.isStream.isReadable(obj2[keys[i]])){
            var str1 = '';
            var str2 = '';
            var goAhead = 0;
            obj1[keys[i]].on("data", function (chunk) {
                str1 += chunk.toString();
            });

            obj2[keys[i]].on("data", function (chunk) {
                str2 += chunk.toString();
            });

            obj1[keys[i]].on("finish", function (err) {
                if(err){
                    return callback(err);
                }
                if(goAhead === 1){
                    if(str1.localeCompare(str2) !== 0){
                        return callback(null, false);
                    }
                }else{
                    goAhead += 1;
                }
            });
            obj2[keys[i]].on("finish", function (err) {
                if(err){
                    return callback(err);
                }
                if(goAhead === 1){
                    if(str1.localeCompare(str2) !== 0){
                        return callback(null, false);
                    }
                }else{
                    goAhead += 1;
                }
            });
        }else if(typeof obj1[keys[i]] === 'object' && !Buffer.isBuffer(obj1[keys[i]])) {
            return objectsAreEqual(obj1[keys[i]], obj2[keys[i]], callback);
        }
    }
    return callback(null, true);
}

if(!fs.existsSync("./big.file")) {
    const file = fs.createWriteStream("./big.file");
    for(let i=0; i<= 1e6; i++) {
        file.write('Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.\n');
    }

    file.end();
}


var obj = {
    key1: "john",
    key2: fs.createReadStream("./big.file"),
    key3: {
        sk1: "Hello",
        sk2: "ashdjg"
    },
    key4: null,
    key5: undefined
};

assert.callback("test Encryption/Decryption in memory", function (callback) {
    crypto.encryptObject(obj, "123", function (err, data) {
        if(err) throw err;

        crypto.decryptObject(data, "123", function(err, decryptedObj) {
            if(err) throw err;

            objectsAreEqual(obj, decryptedObj, function (err, status) {
                if(err) throw err;

                assert.true(status, "Objects are not equal");
                callback();
            });

        })

    });
},10000);
