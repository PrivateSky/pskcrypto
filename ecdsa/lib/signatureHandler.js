
const crypto = require('crypto');
const ssutil = require("../../ssutil");
const KeyEncoder = require("./keyEncoder")
const spv = require("../../tests/fakes/signaturePersistence").getSPV();




function ECDSA(curve){


    if(!curve){
        curve = 'secp256k1';
    }


    this.generateKeyPair = function() {
        var result = {};
        var ec = crypto.createECDH(curve);
        result.public = ec.generateKeys('hex');
        result.private = ec.getPrivateKey('hex');
        return keysToPEM(result);
    }

    function keysToPEM(keys){
        var result = {};
        var ECPrivateKeyASN = KeyEncoder.ECPrivateKeyASN;
        var SubjectPublicKeyInfoASN = KeyEncoder.SubjectPublicKeyInfoASN;
        var keyEncoder = new KeyEncoder(curve);

        var privateKeyObject = keyEncoder.privateKeyObject(keys.private,keys.public);
        var publicKeyObject =keyEncoder.publicKeyObject(keys.public);

        result.private = ECPrivateKeyASN.encode(privateKeyObject, 'pem', privateKeyObject.pemOptions);
        result.public = SubjectPublicKeyInfoASN.encode(publicKeyObject, 'pem', publicKeyObject.pemOptions);
        return result;

    }

    this.sign = function (privateKey,digest) {
        var sign = crypto.createSign("sha256");

        sign.update(digest);

        var signature = sign.sign(privateKey,'hex');

        return signature;
    }

    this.verify = function (publicKey, digest, signature) {

        var verify = crypto.createVerify('sha256');

        verify.update(digest);

        return verify.verify(publicKey,signature,'hex');
    }
}


function AgentSignatureHandler(agentName){

    var agentHash = ssutil.hashValues(agentName);

    var ecdsa = new ECDSA();

    var keys = spv.getKeys(agentHash);



    if(!keys.private || !keys.public){
        keys = ecdsa.generateKeyPair();
        spv.setKeys(agentHash,keys);
    }


    this.digest  = function(obj){
        var result = ssutil.dumpObjectForHashing(obj);
        var hash = crypto.createHash('sha256');
        hash.update(result);
        return hash.digest('hex');
    }

    this.sign  = function(digest, callback){
        callback(null,ecdsa.sign(keys.private,digest));
    }

    this.verify  = function(digest, signature, callback){
        callback(null, ecdsa.verify(keys.public,digest, signature));
    }

    this.regenerateKeys = function () {
        keys = ecdsa.generateKeyPair();
        spv.setKeys(agentHash,keys);
    }

}


exports.getAgentSignatureHandler = function(agent){
    var signatureHandler = new AgentSignatureHandler(agent);

    return signatureHandler;

}
