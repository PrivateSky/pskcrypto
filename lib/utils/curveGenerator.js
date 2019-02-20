const fs = require('fs');



const rl = require('readline').createInterface({
    input: fs.createReadStream('curves')
});

fd = fs.openSync('ECDSAcurves.js', 'w');
fs.writeSync(fd, 'exports.curves = ');
const curves = {};
rl.on('line', function(line) {
    const splitLine = line.split(',');
    const curveName = splitLine[1].trim();
    const curveParameters = splitLine[0].trim().split('.');

    for(let i=0; i < curveParameters.length; i++){
        curveParameters[i] = parseInt(curveParameters[i]);
    }

    const curveProp = {
        curveParameters: curveParameters
    };

    Object.defineProperty(curves,curveName,{
        value: curveProp,
        writable: true,
        enumerable: true,
        configurable: true
    });

});


rl.on('close', () => {
    const strCurves = JSON.stringify(curves, function (k, v) {
        if (v instanceof Array)
            return JSON.stringify(v);
        return v;
    }, 4)
        .replace(/"\[/g, '[')
        .replace(/\]"/g, ']')
        .replace(/\\"/g, '"')
        .replace(/""/g, '"');
    fs.writeSync(fd, strCurves);
});