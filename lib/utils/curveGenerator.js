const fs = require('fs');



var rl = require('readline').createInterface({
    input: fs.createReadStream('curves')
});

fd = fs.openSync('ECDSAcurves.js', 'w');
fs.writeSync(fd, 'exports.curves = ');
var curves = {};
rl.on('line', function(line) {
    var splitLine = line.split(',');
    var curveName = splitLine[1].trim();
    var curveParameters = splitLine[0].trim().split('.');

    for(var i=0; i<curveParameters.length; i++){
        curveParameters[i] = parseInt(curveParameters[i]);
    }
    var curveProp = {
        curveParameters: curveParameters
    }
    Object.defineProperty(curves,curveName,{
        value: curveProp,
        writable: true,
        enumerable: true,
        configurable: true
    });

});


rl.on('close',() =>{
    var strCurves = JSON.stringify(curves,function(k,v){
        if(v instanceof Array)
            return JSON.stringify(v);
        return v;
    },4)
        .replace(/"\[/g, '[')
        .replace(/\]"/g, ']')
        .replace(/\\"/g, '"')
        .replace(/""/g, '"');
    fs.writeSync(fd,strCurves);
})