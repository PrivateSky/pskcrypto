const ecies = require('../ecies-ge-doa') //import the ECIES module
const crypto = require('crypto'); //import the default crypto module so that we can generate keys
const curveName = require('../lib/crypto').params.curveName; //get the default named curve

const NS_PER_SEC = 1e9;
const iterations = 10
const msgSize = 100
const msgRecipients = 1000

const randomMessage = crypto.pseudoRandomBytes(msgSize)

let receiverECDHPublicKeyArray = [];
let lastReceiverECDHKeyPair;
let curReceiverECDH;
// Generate Alice's EC signing key pair (message sender)
let aliceECSigningKeyPair = crypto.generateKeyPairSync(
    'ec',
    {
        namedCurve: curveName
    }
)
// Generate the ECDH key pairs of all recipients
console.log("Generating ECDH key pairs for " + msgRecipients + " recipients...")
for(let i = 0; i < msgRecipients; i++) {
    curReceiverECDH = crypto.createECDH(curveName)
    receiverECDHPublicKeyArray.push(curReceiverECDH.generateKeys())
    if (i === msgRecipients - 1) {
        lastReceiverECDHKeyPair = {
            publicKey: curReceiverECDH.getPublicKey(),
            privateKey: curReceiverECDH.getPrivateKey()

        }
    }
}
console.log("Recipient ECDH key pairs generated!")

// Start with encryptions
var startTime = process.hrtime();
let encEnvelope;
for (i = 0 ; i < iterations ; ++i) {
    encEnvelope = ecies.encrypt(aliceECSigningKeyPair, randomMessage, ...receiverECDHPublicKeyArray)
}
var totalHRTime = process.hrtime(startTime);
var averageEncTimeSecs = ((totalHRTime[0]* NS_PER_SEC + totalHRTime[1]) / NS_PER_SEC) / iterations

// Do decryptions now
startTime = process.hrtime();
for (i = 0 ; i < iterations ; ++i) {
    ecies.decrypt(lastReceiverECDHKeyPair, encEnvelope)
}
totalHRTime = process.hrtime(startTime);
var averageDecTimeSecs = ((totalHRTime[0]* NS_PER_SEC + totalHRTime[1]) / NS_PER_SEC)  / iterations

console.log("ECIES-GE-DOA Benchmark Inputs: " + msgRecipients + " message recipients, message_size = " + msgSize + " bytes and " + iterations + " iterations per operation.")
console.log("Encryption benchmark results: Average Time = " + averageEncTimeSecs + " (secs)")
console.log("Decryption benchmark results: Average Time = " + averageDecTimeSecs + " (secs)")


