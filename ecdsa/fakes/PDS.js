

function PDS(){
    var data = {};

    this.getPublicKey = function(agent){
        return data[agent];
    }

    this.setPublicKey = function (agent, publicKey) {
        data[agent] = publicKey;
    }

}

exports.getPDS = function(){
    return new PDS();
}