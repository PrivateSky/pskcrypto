'use strict';

const mycrypto = require('../crypto')
const config = require('../config')
const crypto = require('crypto');

// Prevent benign malleability
function computeKDFInput(ephemeralPublicKey, sharedSecret) {
    return $$.Buffer.concat([ephemeralPublicKey, sharedSecret],
        ephemeralPublicKey.length + sharedSecret.length)
}

function computeSymmetricEncAndMACKeys(kdfInput, options) {
    let kdfKey = mycrypto.KDF(kdfInput, options.symmetricCipherKeySize + options.macKeySize, options.hashFunctionName, options.hashSize)
    const symmetricEncryptionKey = kdfKey.slice(0, options.symmetricCipherKeySize);
    const macKey = kdfKey.slice(options.symmetricCipherKeySize)
    return {
        symmetricEncryptionKey,
        macKey
    };
}

function getDecodedECDHPublicKeyFromEncEnvelope(encEnvelope) {
    if (encEnvelope.to_ecdh === undefined) {
        throw new Error("Receiver ECDH public key property not found in input encrypted envelope")
    }
    return mycrypto.PublicKeyDeserializer.deserializeECDHPublicKey(encEnvelope.to_ecdh)
}

function checkEncryptedEnvelopeMandatoryProperties(encryptedEnvelope) {
    const mandatoryProperties = ["to_ecdh", "r", "ct", "iv", "tag"];
    mandatoryProperties.forEach((property) => {
        if (typeof encryptedEnvelope[property] === 'undefined') {
            throw new Error("Mandatory property " + property + " is missing from input encrypted envelope");
        }
    })
}

function createEncryptedEnvelopeObject(receiverECDHPublicKey, ephemeralECDHPublicKey, ciphertext, iv, tag, options) {
    return {
        to_ecdh: mycrypto.PublicKeySerializer.serializeECDHPublicKey(receiverECDHPublicKey, options),
        r: mycrypto.PublicKeySerializer.serializeECDHPublicKey(ephemeralECDHPublicKey, options),
        ct: ciphertext.toString(options.encodingFormat),
        iv: iv.toString(options.encodingFormat),
        tag: tag.toString(options.encodingFormat)
    }
}

function checkKeyPairMandatoryProperties(keyPairObject) {
    const mandatoryProperties = ["publicKey", "privateKey"];
    mandatoryProperties.forEach((property) => {
        if (typeof keyPairObject[property] === 'undefined') {
            throw new Error("Mandatory property " + property + " is missing from input key pair object");
        }
    })
}

function convertKeysToKeyObjects(keysArray, type) {
    let createKey;
    if (!type) {
        type = "public";
    }

    if (type === "private") {
        createKey = crypto.createPrivateKey;
    }

    if (type === "public") {
        createKey = crypto.createPublicKey;
    }

    if (typeof createKey !== "function") {
        throw Error(`The specified type is invalid.`);
    }

    if (!Array.isArray(keysArray)) {
        keysArray = [keysArray];
    }

    const keyObjectsArr = keysArray.map(key => {
        if (typeof key === "string") {
            return createKey(key)
        } else {
            return key;
        }
    });

    if (keyObjectsArr.length === 1) {
        return keyObjectsArr[0];
    }

    return keyObjectsArr;
}

module.exports = {
    computeKDFInput,
    computeSymmetricEncAndMACKeys,
    getDecodedECDHPublicKeyFromEncEnvelope,
    checkEncryptedEnvelopeMandatoryProperties,
    createEncryptedEnvelopeObject,
    checkKeyPairMandatoryProperties,
    convertKeysToKeyObjects
}
