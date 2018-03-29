const ecdsa = require("../../modules/ecdsa/lib/sign").createECDSA('secp256k1');
const assert = require("double-check").assert;

var dataToSign = "ana are mere";

var keyPair = ecdsa.generateKeyPair();

var signature = ecdsa.sign(keyPair.private,dataToSign);

assert.notEqual(signature,null,"Signature is null. Way to go, Bob !");

assert.true(ecdsa.verify(keyPair.public,signature,dataToSign),"Fail at verifying the signature. Nice work, Chase !");