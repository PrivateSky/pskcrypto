
const crypto = require('crypto');
const ssutil = require("../../signsensusDS/ssutil");
const KeyEncoder = require("../keyEncoder");
const spv = require("../ecdsa/fakes/signaturePersistence").getSPV();
const ecdsa = require('../ECDSA');

function AgentSignatureHandler(agentName){
    const agentHash = ssutil.hashValues(agentName);
    const ds = ecdsa.createECDSA();
    let keys = spv.getKeys(agentHash);

    if(!keys.private || !keys.public){
        keys = ds.generateKeyPair();
        spv.setKeys(agentHash,keys);
    }

    this.digest  = function(obj){
        const result = ssutil.dumpObjectForHashing(obj);
        const hash = crypto.createHash('sha256');
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
    const signatureHandler = new AgentSignatureHandler(agent);
    return signatureHandler;
};