const PskCrypto = require("./lib/PskCrypto");
const ssutil = require("./signsensusDS/ssutil");

module.exports = PskCrypto;

module.exports.hashValues = ssutil.hashValues;

if(typeof(___DISABLE_OBSOLETE_ZIP_ARCHIVER_WAIT_FOR_BARS) === 'undefined'){
    module.exports.PskArchiver = require("./lib/psk-archiver");
}

module.exports.DuplexStream = require("./lib/utils/DuplexStream");

module.exports.isStream = require("./lib/utils/isStream");