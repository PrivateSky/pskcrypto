
const crypto = require('crypto');
const ssutil = require("../../signsensusDS/ssutil");
const KeyEncoder = require("./keyEncoder");
const spv = require("../fakes/signaturePersistence").getSPV();
const ecdsa = require('./ECDSA');

function AgentSignatureHandler(agentName){
    var agentHash = ssutil.hashValues(agentName);
    var ds = ecdsa.createECDSA();
    var keys = spv.getKeys(agentHash);

    if(!keys.private || !keys.public){
        keys = ds.generateKeyPair();
        spv.setKeys(agentHash,keys);
    }

    this.digest  = function(obj){
        var result = ssutil.dumpObjectForHashing(obj);
        var hash = crypto.createHash('sha256');
        hash.update(result);
        return hash.digest('hex');
    };

    this.sign  = function(digest, callback){
        callback(null,ecdsa.sign(keys.private,digest));
    };

    this.verify  = function(digest, signature, callback){
        callback(null, ecdsa.verify(keys.public,digest, signature));
    };

    this.regenerateKeys = function () {
        keys = ecdsa.generateKeyPair();
        spv.setKeys(agentHash,keys);
    };
}

exports.getAgentSignatureHandler = function(agent){
    var signatureHandler = new AgentSignatureHandler(agent);
    return signatureHandler;
};