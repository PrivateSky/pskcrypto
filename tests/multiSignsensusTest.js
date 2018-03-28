
var ss = require("../../signsensus/lib/sign");

require("../../../engine/core").enableTesting();

var safeBox = ss.getAgentSafeBox("testAgent", 63);

var assert = require("double-check").assert;


var test = $$.flow.describe("signatureTest",{
    public:{
        counter: "int",
        result: "int"
    },
    start:function(callback){
        this.result=0;
        this.counter=0;
        this.callback=callback;
        this.obj = {
            name:"Hello World"
        }

        this.digest = safeBox.digest(this.obj);

        for(var i=0; i<10; i++){
            var t = process.hrtime();

            safeBox.sign(this.digest, this.getSignature);

            t = process.hrtime(t);
           // var time_in_sec = t[0] + t[1]/1000000000;
           // assert.true(time_in_sec<1, "generating new public key took too long");
            //console.log('Signing + generating a new public key took %d seconds (or %d milliseconds)', t[0] + t[1]/1000000000, t[1]/ 1000000);
        }
    },
    getSignature:function(err,signature){
        this.result++;
        this.signature = signature;
        assert.notEqual(this.signature, null, "Signature is null!");
        safeBox.verify(this.digest, signature, this.printResults);
    },

    printResults:function(err,isGood){
        this.result--;
        this.counter++;
        assert.equal(this.result,0, "Failed");
        assert.equal(isGood, true, "Fail to verify signature");
        if(this.counter==10) {
            this.callback();
        }
    }
})
assert.callback("Multisignsensus test",function(callback){
    test().start(callback);
})


