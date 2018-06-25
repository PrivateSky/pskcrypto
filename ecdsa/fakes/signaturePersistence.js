const safebox = require("./safebox").getSafebox();
const pds = require("./PDS").getPDS();


function SignaturePersistenceProvider(){

    this.getKeys = function(agent){
        var keys = {};

        keys.private = safebox.getPrivateKey(agent);
        keys.public = pds.getPublicKey(agent);

        return keys;
    }

    this.setKeys = function(agent, keys){
        safebox.setPrivateKey(agent, keys.private);
        pds.setPublicKey(agent, keys.public);
    }
}


exports.getSPV = function () {
    return new SignaturePersistenceProvider();
}