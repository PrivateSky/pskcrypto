const {generateSecret: generate} = require('../runtime/generate.js');
module.exports.generateSecret = async function generateSecret(alg, options) {
    return generate(alg, options);
};
