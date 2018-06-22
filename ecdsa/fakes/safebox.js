
function Safebox(){
    var data = {};

    this.getPrivateKey = function(agent){
        return data[agent];
    }

    this.setPrivateKey = function (agent, privateKey) {
        data[agent] = privateKey;
    }

}

exports.getSafebox = function(){
    return new Safebox();
}