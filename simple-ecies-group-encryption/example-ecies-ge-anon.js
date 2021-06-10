const ecies = require('./ecies-ge-anon') //import the ECIES module
const assert = require('assert').strict;
const crypto = require('crypto'); //import the default crypto module so that we can generate keys
const curveName = require('./lib/crypto').params.curveName; //get the default named curve

// The message we want to transmit, as a Buffer, which is what the encrypt() function expects
const plainTextMessage = Buffer.from('hello world');
const totalReceivers = 5; // we want to encrypt the message for 5 different recipients
let receiverECDHPublicKeyArray = [];
let receiverECDHKeyPairArray = [];
let curReceiverECDH;
// Generate the ECDH key pairs of all recipients
for(let i = 0; i < totalReceivers; i++) {
    curReceiverECDH = crypto.createECDH(curveName)
    receiverECDHPublicKeyArray.push(curReceiverECDH.generateKeys())
    receiverECDHKeyPairArray.push({
        publicKey: curReceiverECDH.getPublicKey(),
        privateKey: curReceiverECDH.getPrivateKey()
    })
}
// Encrypt the message for all the intended recipients
let encEnvelope = ecies.encrypt(plainTextMessage, ...receiverECDHPublicKeyArray);
console.log('Encrypted Envelope:')
console.log(encEnvelope)

// ... The encrypted envelope is somehow transmitted to all the recipients
// ... Each recipient receives the encrypted envelope

// Get all the ECDH public keys for which this message was encrypted for
let decodedRecipientECDHPublicKeyArray = ecies.getRecipientECDHPublicKeysFromEncEnvelope(encEnvelope)
// ... each receiver here should attempt to find her corresponding ECDH private key
// ... if no corresponding private key is found, the receiver should throw the message away
let decMessage;
// We now decrypt with each recipient's ECDH key pair
for(let i = 0 ; i < totalReceivers ; i++) {
    decMessage = ecies.decrypt(receiverECDHKeyPairArray[i], encEnvelope)
    assert(Buffer.compare(decMessage, plainTextMessage) === 0, "MESSAGES ARE NOT EQUAL")
}
// Here is the decrypted message!
console.log('Decrypted message is: ' + decMessage);

