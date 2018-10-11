const PskCrypto = require("./lib/PskCrypto");

const ssutil = require("./signsensusDS/ssutil");

const uidGenerator = require("./lib/uidGenerator").createUidGenerator(20, 32);

module.exports = PskCrypto;

module.exports.hashValues = ssutil.hashValues;

module.exports.generateUid = uidGenerator.getNbytes;
