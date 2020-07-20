require("../../../psknode/bundles/testsRuntime");
const assert = require("double-check").assert;
const crypto = require("../lib/PskCrypto");

const keys = crypto.generateKeyPair();
const pemFormattedKeys = crypto.convertKeys(keys.privateKey, keys.publicKey);

assert.begin();

const content = "some data";
const signature = crypto.sign(content, pemFormattedKeys.privateKey);
assert.true(crypto.verify(content, pemFormattedKeys.publicKey, signature), "Failed to verify signature");

assert.end();