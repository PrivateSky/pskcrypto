const PskCrypto = require("./lib/PskCrypto");

const ssutil = require("./signsensusDS/ssutil");

const uidGenerator = require("./lib/uidGenerator").createUidGenerator(200, 64);

module.exports = PskCrypto;

module.exports.hashValues = ssutil.hashValues;
module.exports.uidGenerator = uidGenerator;
// module.exports.generateUid = uidGenerator.generateUid;
