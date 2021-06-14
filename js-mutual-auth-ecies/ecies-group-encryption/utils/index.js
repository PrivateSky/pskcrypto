'use strict';

const sender = require('./sender')
const recipient = require('./recipient')

module.exports = {
    generateKeyBufferParams: sender.generateKeyBufferParams,
    senderMultiRecipientECIESEncrypt: sender.senderMultiRecipientECIESEncrypt,
    getRecipientECDHPublicKeysFromEncEnvelope: recipient.getRecipientECDHPublicKeysFromEncEnvelope,
    receiverMultiRecipientECIESDecrypt: recipient.receiverMultiRecipientECIESDecrypt,
    parseKeyBuffer: recipient.parseKeyBuffer
}


