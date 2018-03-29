var KeyEncoder = require('../../modules/ecdsa/lib/keyEncoder');
var ECPrivateKeyASN = KeyEncoder.ECPrivateKeyASN;
var SubjectPublicKeyInfoASN = KeyEncoder.SubjectPublicKeyInfoASN;

const crypto = require('crypto');
const sign = crypto.createSign('sha256');
const verify = crypto.createVerify('sha256');

var keyEncoder = new KeyEncoder('secp256k1');


const alice = crypto.createECDH('secp256k1');
const aliceKey = alice.generateKeys('hex');

const bob = crypto.createECDH('secp256k1');
const bobKey = bob.generateKeys('hex');

var privateKey = alice.getPrivateKey('hex');
var publicKey = aliceKey;

var privateKeyObject = keyEncoder.privateKeyObject(privateKey,publicKey);

var privateKeyPEM = ECPrivateKeyASN.encode(privateKeyObject, 'pem', privateKeyObject.pemOptions)
console.log(privateKeyPEM);





sign.update('some data to sign');

var publicKeyObject =keyEncoder.publicKeyObject(publicKey);

var publicKeyPEM = SubjectPublicKeyInfoASN.encode(publicKeyObject, 'pem', publicKeyObject.pemOptions)

const signature = sign.sign(privateKeyPEM,'hex');



verify.update('some data to sign');
console.log(signature);

console.log(verify.verify(publicKeyPEM,signature,'hex'));