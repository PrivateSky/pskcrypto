const crypto = require('./webcrypto.js');
module.exports = crypto.getRandomValues.bind(crypto);
