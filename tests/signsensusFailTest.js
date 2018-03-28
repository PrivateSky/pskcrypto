
var ss = require("../../signsensus/lib/sign");

require("../../../engine/core").enableTesting();

var safeBox = ss.getAgentSafeBox("testAgent");
var assert=require('double-check').assert;
var test = $$.flow.describe("signatureTest",{
    public:{
        result: "int"
    },
    start:function(callback){
        this.obj = {
            name:"Hello World"
        }
        this.result=0;
        this.callback=callback;
        this.digest = safeBox.digest(this.obj);
        safeBox.sign(this.digest, this.getSignature);
    },
    getSignature:function(err,signature){
        this.signature = signature;
        this.result++;
        assert.notEqual(signature,null,"Signature is null");
        this.obj.name = "Hello World!!!!!!!!!";
        this.digest = safeBox.digest(this.obj);
        safeBox.verify(this.digest, signature, this.printResults);
    },
    printResults:function(err,isGood){
        this.result--;
        assert.equal(this.result,0,"Failed in callback sequence");
        assert.notEqual(isGood,true,"Fail - Signature checks out");
        this.callback();
    }
});
assert.callback("Signsensus fail test",function(callback){
    test().start(callback);
});



