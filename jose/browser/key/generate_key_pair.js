const {generateKeyPair: generate} = require('../runtime/generate.js');
module.exports.generateKeyPair = async function generateKeyPair(alg, options) {
    return generate(alg, options);
}
