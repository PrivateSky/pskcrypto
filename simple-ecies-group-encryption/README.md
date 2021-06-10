# Simple, ECIES-Based, Group Encryption

The problem that we are concerned with here is related to that of encrypting a message, i.e., arbitrary data, so that only a set of *qualified users* can decrypt it. The sender of a message should be able to select, on a per-message basis, the qualified user, or intended recipient, set. This repository contains simplified implementations of such a group encryption primitive.

# Disclaimer & Dependencies
The code of this repository was developed with the intent of being integrated in the [OpenDSU](https://github.com/PrivateSky/OpenDSU) codebase, as part of the [PharmaLedger H2020](https://pharmaledger.eu/) project's efforts. The group encryption implementations provided here are based on the ECIES implementation of our [js-mutual-auth-ecies](https://github.com/cpatsonakis/js-mutual-auth-ecies) repository. The ECIES implementation from the latter repository was, essentially, taken as it were and, along with the necessary supplementary modules, is included in the `lib/` folder. For more information regarding the ECIES implementation, we refer the interested reader to our extensive documentation in the aforementioned repository. We stress that none of our implementations introduce external dependencies and that, in the background, they are developed based on NodeJS's `crypto` module, which is essentially a wrapper of the OpenSSL C-based library implementation.

# Preconditions & Assumptions

The purpose of this section is to document the preconditions and assumptions that formed the basis of our reasoning for designing and implementing the group encryption schemes provided here. This will, hopefully, provide the interested reader with preliminary insight regarding the intended and practical use of this repository's implementations. Moreover, it will allow us to gradually clarify, in more detail, the exact nature of the problem that we are trying to solve, as well as, other subtle details that, in our view, are relevant and informative.

Undoubtedly, the term *group*, especially from a cryptographic point of view, is inherently vague and warrants further clarification. In our context, we employ a simplistic approach and define a group as a non-empty set G={pk<sub>1</sub>, ..., pk<sub>n</sub>}, n>0, where, for any i &#x2208; [1,n], pk<sub>i</sub> denotes the public key of the group's i<sup>th</sup> member. For instance, the set G<sub>4</sub>={pk<sub>1</sub>, pk<sub>2</sub>, pk<sub>3</sub>, pk<sub>4</sub>} defines a group that is comprised by four distinct members, for which it provides a listing of their respective public keys.

Clearly, even in our simplistic scenario, it is evident that the description provided above is nothing but a, partial one can argue, representation of a group. Indeed, in order to formulate a comprehensive description of what constitutes a group, one needs to address several issues that are far more challenging than its representation. An intuitive and informal list of such issues can be summarized as follows:

1. How is a group established?
1. How is a group identified?
1. Who, or what mechanism, controls group membership?
1. How does one discover cryptographic material related to the group, e.g., cryptographic keys and other auxiliary parameters/values?

All of the aforementioned considerations are (somewhat) related to what is commonly referred to as the *group management* problem. While this is an extremely important topic, we stress that it is out of the scope of this work. More specifically, and since we are concerned with group encryption here, we assume that there exists an external mechanism that allows an entity to **securely resolve** the set G. Depending on the context, one has several options for secure resolution of cryptographic material, the most prominent of which, especially for asymmetric key pairs, is the SSL/TLS hierarchy. However, there are other alternatives available that build on more modern advancements and provide for increased fault-tolerance in terms of trust, as well as, overall security by leveraging distributed ledger technologies (DLTs), e.g., blockchains. 

The group representations that we consider here are based on public key cryptography, which imposes severe limitations on the set of group scheme constructions that can be coupled with the group encryption schemes provided here. However, even if we approached this issue from the opposite direction, i.e., if we first tackled the topic of group management, which by definition solidifies a group's cryptographic material, it is evident that similar limitations, and perhaps more stringent, would apply for the group encryption scheme. In short, there is no one size fits all and in the context of this exercise, we have decided to proceed with the modest assumption of employing public key cryptography as a basis.

In the interest of clarity, we stress that we are not concerned here with the message delivery system that will be used to transmit the encrypted message to the group. For instance, the transport mechanism and even security properties related to, e.g., whether a message is delivered to all group members, or a subset of them, are considered out of this exercise's scope.

Conceptually, when one is tasked to provide a technical solution to a problem, or design a solution for one or more use cases, it is rarely the case that there are no additional constraints or limitations. For instance, based on the discussion up to this point, one could argue that employing public key cryptography as a basis is a constraint. From a theoretical cryptography point of view, and more specifically, when dealing with public key cryptosystems over elliptic curves, which is the case in our context, one could argue that we still have mathematical tools at our disposal, such as operations on the underlying elliptic curve group, that would allow us to engage in the dark art of crypto magic. However, we stress that this is not the case here. Indeed, from a technical standpoint, we have a limited set of tools at our disposal that can only be used in a black-box fashion, an explicit list of which is as follows: 1) hash functions, i.e., mainly SHA-2-256, 2) symmetric ciphers, typically some instantiation of AES (not ECB!), 3) HMACs, 4) digital signatures, more specifically, ECDSA and, 5) ECDH(E), i.e., either ephemeral or not. A knowledgeable reader will notice that these tools, especially when employed in a black-box fashion, are inadequate to provide efficient solutions for multi-party protocols.

# Requirements

We now shift our attention on the group encryption scheme itself and provide a high-level description of technical requirements that the implementations should abide by. 

Arguably, the most natural starting point since we are dealing with encryption is the ciphertext itself. More specifically, in the context of group encryption, the size of the ciphertext is an important factor. Indeed, it would be beneficial if its size were some sub-linear function of the group's cardinality, or, ideally, constant. However, for the application settings that concern us, the size of the ciphertext is not that important, i.e., it is considered acceptable even if the size of the ciphertext is a linear function of the group's cardinality. Clearly, a linearly sized ciphertext imposes a linear communication complexity, which is a fact that we are conscious of and deem as acceptable in our context.

The state maintained by users, i.e., group members, should be reasonably bounded, which is a point that warrants a small level of clarification. Typically, multi-party cryptographic protocols involve parameters that, in many cases, are linear to the maximum number of participants. Put simply, when a multi-party protocol is setup, it generally is the case that an upper bound on the participant set is specified. However, these parameters, typically, are reusable across an arbitrary number of protocol invocations. In our context, these aforementioned storage requirements are acceptable.

The computational complexity, or efficiency, of encryption and decryption is another aspect that, as hinted by the discussion regarding ciphertext size, is not a matter of grave concern for us. Loosely speaking, for reasonably-sized messages and group cardinalities, we consider an execution time that lies in the order of a few seconds as acceptable for these algorithms.

When discussing the topic of secure communication in two party settings, it is standard practice to employ an authentication encryption scheme, i.e., to guarantee confidentiality and integrity. We require that our construction(s) provide the same properties, albeit in a multi-party, or group, setting.

Anonymity is, undoubtedly, an important aspect of secure communication. For instance, and assuming a two party setting for ease of description, there are schemes in which the sender is completely anonymous, both to a potential man-in-the-middle (MITM), as well as, the intended message recipient. ECIES, which we employ as a building block, is an encryption scheme that provides the aforementioned sender anonymity guarantees. For our use cases, depending on the application context, there are cases where sender anonymity is required and others where it is not, i.e., we need to be able to support both. On a similar note, one might require to, instead, preserve the anonymity of the intended recipient in some cases. We stress that for our use cases receiver anonymity is discouraged.

Group backward secrecy is, informally, defined as the inability of a group member to decrypt messages that were sent to the group prior to her admission to the group. Correspondingly, group forward secrecy is, informally, defined as the inability of a member to decrypt messages that are sent to the group following her departure from the group. The construction(s) must provide for both of these properties.

# Overview

In the following, we provide a succinct overview of the ECIES-based group encryption (GE) implementations that one can find in this repository:

 - [ECIES-GE-ANON](#ecies-ge-anon): Group encryption implementation in which the sender remains completely anonymous.
 - [ECIES-GE-DOA](#ecies-ge-doa): In this implementation, the sender's identity (public key) is transmitted in the clear and data origin authentication (DOA) is guaranteed via a digital signature.

In the remainder of this documentation, and especially in sections revolving around API specifications, we will be assuming the default cryptographic configuration options, an elaborate description of which is provided in our [js-mutual-auth-ecies](https://github.com/cpatsonakis/js-mutual-auth-ecies) repository.

Lastly, in the interest of clarity, we stress that all implementations assume that the sender is **honest**. We refer the interested reader to the [Security Drawbacks](#security-drawbacks) section for further details on this matter.

# ECIES-GE-ANON

This implementation provides for sender anonymity, as was previously highlighted. The main idea behind this group encryption construction is as follows. Assuming a recipient group of cardinality `n`, the sender invokes `n` instances of standard ECIES to encrypt a randomly generated array of bytes, to which we refer to as *key buffer* and denote as `kb`. This buffer is comprised of three parts, a symmetric cipher key `sk` and two KMAC keys `mk1` and `mk2`, such that `kb = sk||mk1||mk2`, where `||` denotes concatenation. The key `mk2` is used to compute a MAC (denoted as `rtag`) on the serialization of the `n` instances of ECIES, i.e., to guarantee their integrity. The key `sk` is used to encrypt the plaintext, which produces a ciphertext `ct`. The key `mk1` is used to guarantee integrity of `ct`, along with the symmetric cipher's `iv`.

## Quick Start Guide
If you are interested in just using this version of the implementation, without digging into the nitty gritty details, in the following, we provide a simple usage example, in which some entity (which is always anonymous in this version of the implementation) wants to send a message to five distinct recipients:
```js
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
```
This code sample is based on the one provided in the `example-ecies-ge-anon.js` file.

## API Specification

In this section, we document the main functions that are exposed by this module, which are defined as follows:
<br>

>### getRecipientECDHPublicKeysFromEncEnvelope(encEnvelope)
- #### **Description:** This is a helper function that is intended to be used by the receivers so that they can, individually, easily get, on input an encrypted envelope object (described below), the public ECDH keys of the intended recipients as specified by the sender of the message.
- #### **encEnvelope**: An encrypted envelope object (described below).
- #### **Returns**:  An array of deserialized (decoded) ECDH public keys.

This function should always be invoked in a `try-catch` block as it can throw exceptions for various reasons. The receiver of an encrypted envelope needs to infer which specific ECDH private key she should input to the decryption function (described later on in this section). To achieve this, the receiver is, typically, expected to first invoke this function and, subsequently, query w/e database she uses for key storage. Clearly, if a corresponding key cannot be located, the envelope should be discarded as the decryption function will throw an error.

>### encrypt(message, ...receiverECDHPublicKeys)
- #### **Description:** The group encryption function of this implementation.
- #### **message**: The message as a `Buffer` type that we want to encrypt and send across the wire.
- #### **receiverECDHPublicKeys**: The ECDH public keys of the intended recipients.
- #### **Returns**:  An encrypted envelope object (described below).

This function should **always** be invoked in a `try-catch` block as it can throw exceptions for various reasons, e.g., improperly formatted keys, keys that are not on the configured curve etc. The encrypted envelope object returned by this function has the following structure:
```json
{
  "recvs": "W3sidG9fZWNkaCI6IkJFQ1llL0lHd1VCMUhQcEtWQWgvS1N1aUFRaGlVYmdtWlF4a0VtUUZEOHg1S09zcnk4T012N1FabUtDazZ2elJwM0VxWWh4cFZzak4reEZwMk4rbzdCVT0iLCJyIjoiQkRjc0gzV0V4WnNnWkM3cWc0bHJTbGZKVDFqRHo3citZeTdhOCtVS1ZtQWpEQ2pLTmR6QVEzRnlOTCtidlRyMmRzVnc0L1Fna2R2ak5zNm5sd2k1WElJPSIsImN0IjoiTndzelFITHd0dENEU3Q1em9uWG9zYSttTnNlTkFoZUVBSDcwd2FsYkszUTNuclp1dGZoNDV0aUJzS1U5TFBROFNpRWpHWFB4Kzg5Z1M4cGhKNWxWYUE9PSIsIml2IjoiNlNkcW82VC9TZnZMa1hKTVdGamNlUT09IiwidGFnIjoiajhvc0lGRWtZMEpRU2YxTllvZ1FHUCt6L1RUWCtjZDFJcWRQdzFJTDU1az0ifSx7InRvX2VjZGgiOiJCSUJhNE9IbHc5NTJzMDBINk1VczB6VVBSanJLUElpVm5BS040N2tXWCtVNDV1TWpFeGhVbDFORGhzUzQ0ZDY4WjhDQnRrNjYrekgxUnFBRlpncUhnR0E9IiwiciI6IkJNMEk5bWZYSlhHN2tVVUk4UlB6eGQ2aUo3Vi91MXBDRmFnS2pqTDJFUTZBUElQTEpUbHhma1N0aVNtcXE5MjllQ1hyUjQwM0QzR2lVZVlnbXd6cXp0QT0iLCJjdCI6Ii9tdE5uRmJqenRwdlVSalVuUzZDWU5vUUtyZVdXd0JIZTlYTmt2a1B1VHdnTytROXBBYVhzRWNiaitrbnhhNlhrVXJtRm85aFZKZzlwN3M0ZU5EL3p3PT0iLCJpdiI6IkhBeGZBWDB4bFlLMTRtcThHRFpzQVE9PSIsInRhZyI6IldDWFcxREZQSHpOOEQyOVZaNWlPaTFtb3h1REFNb0VkdVRwOVdDc2hibG89In0seyJ0b19lY2RoIjoiQlA3WjF1NmZEZDgwSitPL0IzMkMzMkE0VnJQTGdCMnRIOU5FdjFmSi9HR2N1ZkJEaDNERkJuU0dpUXhUV1lURml1dXVkbzZvVVpTMEVRdVp6dFUwc3dRPSIsInIiOiJCRGNHMEFLVXZVeGhnSmUybFJ4Q29adHpKamgvS3RUVmcxSTRhTTBiOGc1UmFCZktQVStRbTlkRnMyQmNTd3hQY1UxOURaNEI5NjNwbWRFOWJPaDN5VWM9IiwiY3QiOiI0SmVTRlI2elNUT0k3K1RiaHhFcmtlMWdpeVozc2RBa2lpK1BEMy9TTzVsR3JEQWpHUmFWZ3d6NlJuQmhDZi9ZcmtsMWlPaGhyRzdPMFhieGxUMHhHQT09IiwiaXYiOiJiU1dtQi9pSWlSeER2L1dsUXJva1ZnPT0iLCJ0YWciOiJIK0tMYTRhUForZWI0T1VKZSszYTZIWm5HZ1h1bzVwZEJLMzdEZFlybEF3PSJ9LHsidG9fZWNkaCI6IkJDbFdFOVdjdm96SG9SRHllaGZEcFVVdmxldy81VTUzYm1ZK2RXUlFLQm9CVHpReU0yOU9jT2ZVVVhsK3NYQWMwekhsbTJkSHdzbDRBU2hPYWJpTHN0MD0iLCJyIjoiQkF2aGx0NHFSdWJ3UjlzbDNaaWh6MGJ0ZS9MSStEVmNWeVVGZFJKa0NDTWo4OWlWTzN3YXRoNWtEdmVPZGNRR2xnblVMdDBqTXM3VGNIZTEzMzlyVTFvPSIsImN0IjoiY0xYUDBmTmd1akd0M3htTHVlbFJrOHh5Z21pRGlMVDFwWFUwUEwwenZxMjkxUVJLWnU3N3F6cUVESEhlSFBNbG1OaFR6bUZEUHdkQ1FveFI0RlFKcEE9PSIsIml2IjoiQVA5NWJzVFRnaS9oc2JjNUZkSEJvUT09IiwidGFnIjoiMHd0RU9kZ21za0lLd3VsbkxyaFRsaDBscENsK1hEZUd5MS9WN0NUekV6VT0ifSx7InRvX2VjZGgiOiJCS2JRNzgyeTB3eFQ3dFFlY1l4ejY3T1lCU2EzSTN0NnphNTVPSEhqVE5kM1l3ZTU5dENWQ2NkYWRwUWxPdEJpNGQwN3RYVVRkaEYzVmhWNjRyNG5oY1U9IiwiciI6IkJEYlR1bkNTRWZTcVVkcUIzclJTK3pRNFQwOFZuYk5WaEloRURybkNkYk1LQk8yQ1FlOWIxSGI3OUQxZ0hlRUxVSFlwUlpyc203Tzd2OHJLZEFUbmh3QT0iLCJjdCI6Im43ekxBaUVwK0krZUhoSWlLbVNvM1dLMEtNVU42bG5PbFVvekR6YWFjREsvdWVaRXh0NXZiQVpFSVp1UU9oOTF6UGVHcGVBWmxkSUlOVW5scVhLb2NBPT0iLCJpdiI6IlB3S0FyYWNYTW5NUmdvUVAydkh0L1E9PSIsInRhZyI6Im1jUVg1ZTRna0JOdE9uRkVaVUhKQThiM28yOG1PWE9EUG9EMHp5cXNNMVE9In1d",
  "rtag": "53e0wSQ9+KQt3fFoDwwfdkBXrXKf9zWMNet3S3zSvVo=",
  "ct": "8NWbwVFl/n47GyxoAv1wbA==",
  "iv": "R7ICV7eli0zK0e+kvM+FnA==",
  "tag": "sGD1ml2ss/8hxlLGakaJklSQtJZNarhEPxpt3Np7pSA="
}
```

A succinct overview of the fields of an encrypted envelope object is as follows:
1. `recvs`: The `n` serialized ECIES instances.
1. `rtag`: The MAC for the `recvs` field.
1. `ct`: The ciphertext.
1. `iv`: The initialization vector of the symmetric cipher.
1. `tag`: The output of the KMAC function for the ciphertext.
<br>

>### decrypt(receiverECDHKeyPair, encEnvelope)
- #### **Description:** The group encryption function of this implementation.
- #### **receiverECDHKeyPair**:  An object with properties `publicKey` and `privateKey` that encompass the receiver's ECDH key pair.
- #### **encEnvelope**: An encrypted envelope object as is output by the `encrypt()` function.
- #### **Returns**:  The decrypted message as a `Buffer` type.

This function should **always** be invoked in a `try-catch` block as it can throw exceptions for various reasons.

## Benchmark

A simple benchmark for this implementation is provided in the `bench/bench-ecies-ge-anon.js` file. You can tune the number of intended recipients and the size of the message by modifying the `msgRecipients` and `msgSize` variables at the beginning of the file. The output of this script is along the lines of:

```
Generating ECDH key pairs for 1000 recipients...
Recipient ECDH key pairs generated!
ECIES-GE-ANON Benchmark Inputs: 1000 message recipients, message_size = 100 bytes and 10 iterations per operation.
Encryption benchmark results: Average Time = 2.1639703336 (secs)
Decryption benchmark results: Average Time = 0.0230003147 (secs)
```
for `msgRecipients=1000` and `msgSize=100`, which was executed on a fairly resource-constrained VM.

# ECIES-GE-DOA

This implementation internally invokes the anonymous group encryption primitive (described previously) and provides for data origin authentication by appending to the envelope the EC public key of the sender, which is transmitted in the clear, and a digital signature. The latter is computed based on the two MACs that are included in the envelope.

## Quick Start Guide
If you are interested in just using this version of the implementation, without digging into the nitty gritty details, in the following, we provide a simple usage example, in which `Alice` wants to send a message to five distinct recipients:
```js
const ecies = require('./ecies-ge-doa') //import the ECIES module
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
// Generate Alice's EC signing key pair (message sender)
let aliceECSigningKeyPair = crypto.generateKeyPairSync(
    'ec',
    {
        namedCurve: curveName
    }
)
// Encrypt the message for all the intended recipients
let encEnvelope = ecies.encrypt(aliceECSigningKeyPair, plainTextMessage, ...receiverECDHPublicKeyArray)
console.log('Encrypted Envelope:')
console.log(encEnvelope)

// ... The encrypted envelope is somehow transmitted to all the recipients
// ... Each recipient receives the encrypted envelope

// Get all the ECDH public keys for which this message was encrypted for
let decodedRecipientECDHPublicKeyArray = ecies.getRecipientECDHPublicKeysFromEncEnvelope(encEnvelope)
// ... each receiver here should attempt to find her corresponding ECDH private key
// ... if no corresponding private key is found, the receiver should throw the message away
let decEnvelope;
// We now decrypt with each recipient's ECDH key pair
for(let i = 0 ; i < totalReceivers ; i++) {
    decEnvelope = ecies.decrypt(receiverECDHKeyPairArray[i], encEnvelope)
    assert(Buffer.compare(decEnvelope.message, plainTextMessage) === 0, "MESSAGES ARE NOT EQUAL")
}
// Here is the decrypted message!
console.log('Decrypted message is: ' + decEnvelope.message);
```
This code sample is based on the one provided in the `example-ecies-ge-doa.js` file.

## API Specification

In this section, we document the main functions that are exposed by this module, which are defined as follows:
<br>

>### getRecipientECDHPublicKeysFromEncEnvelope(encEnvelope)
- #### **Description:** This is a helper function that is intended to be used by the receivers so that they can, individually, easily get, on input an encrypted envelope object (described below), the public ECDH keys of the intended recipients as specified by the sender of the message.
- #### **encEnvelope**: An encrypted envelope object (described below).
- #### **Returns**:  An array of deserialized (decoded) ECDH public keys.

This function should always be invoked in a `try-catch` block as it can throw exceptions for various reasons. The receiver of an encrypted envelope needs to infer which specific ECDH private key she should input to the decryption function (described later on in this section). To achieve this, the receiver is, typically, expected to first invoke this function and, subsequently, query w/e database she uses for key storage. Clearly, if a corresponding key cannot be located, the envelope should be discarded as the decryption function will throw an error.

>### encrypt(senderECSigningKeyPair, message, ...receiverECDHPublicKeys)
- #### **Description:** The group encryption function of this implementation.
- #### **senderECSigningKeyPair**: An object with properties `publicKey` and `privateKey` that encompass the sender's EC signing key pair.
- #### **message**: The message as a `Buffer` type that we want to encrypt and send across the wire.
- #### **receiverECDHPublicKeys**: The ECDH public keys of the intended recipients.
- #### **Returns**:  An encrypted envelope object (described below).

This function should **always** be invoked in a `try-catch` block as it can throw exceptions for various reasons, e.g., improperly formatted keys, keys that are not on the configured curve etc. The encrypted envelope object returned by this function has the following structure:
```json
{
  "recvs": "W3sidG9fZWNkaCI6IkJJcTh0VDBOVG1CTjJkdlQ1MnVESXNjQ2JVOVpWL0tyaURkNEtNU1hhZHQ4SnJuQmxRRDNaUGd0R3hsOG1ZazNCdUpqRFBCVENNamtVUWYvVUU3bU1MVT0iLCJyIjoiQk9tdkQycmNrU3pIQkdsUVFSSFpNdzRhUEtWNWtzUVJqbWZaWi8reFZpaDZtRnArUWUyS3NkTkJZWnZaTlBld2JYU0xSNEx5MFY5WFRkRWtoZkN6OGprPSIsImN0IjoiVFpsbzR2MkYzRndWRENNVi9ZK0dWckxMY3grV0FGZVkzL3VCRDBTOTIwNyt3Q1h1bUY5bVVxRG8xYnRydGxvMkM0OVMyRWxPamxZRG9helJxdXUxRGc9PSIsIml2IjoiYXdNUWRjaElURERZVW53bW1XVThGQT09IiwidGFnIjoiVWdldGZ3VUFQUG9OTlJvcFRhMXBIWVN6U3l2azQzRDAyVFBjM0FVZ1RuQT0ifSx7InRvX2VjZGgiOiJCQzBiWm1ZMTljR1pTQUpJV1EvbEs5WTFTeHl3UGVjNHpKcnFRanlRU1hBdDY5UFFyd1BIaFBRZXl2Y2xUMURySGJycnV3VWRSTEl2ZjNvaTl0cjIyenc9IiwiciI6IkJPK3FobFdMenIvRUkwWGdVSGsyNGtOMy95ZGJsOXFyQXdBbUxoVk90UHlvOTNUckJTaHN1VnRobENRTjl1aEdPT2R2VUQ2THBsanFtUUh6cFRVaS9Yaz0iLCJjdCI6IjNOOVBLczhpYVhWVHllS1lyb1pESWQ5QU01Zis2WkFvOENZY1l2cHlsTWp4UFgvQ2hib1M4VFd2eE96UjBEWjJuNm4zUEFhVGVDNVJNMkYreDBjb2RnPT0iLCJpdiI6IlZJK0xSSWNPdGMxcWRKVlZyOUVMSHc9PSIsInRhZyI6IklKRktCMk1JRkFFWktuZ2V2UzhpVC9UZkhvQkJyQjVZMnBMN2U1aWIwYm89In0seyJ0b19lY2RoIjoiQkpoVHhSYktPYVR4Q3ZCVks5UnFwYUplcEw4TzAzMmVpMStXemdjMHBGQkR6WFlDVE1ST0p5YWlLUXJqaTlhUkV4TTZJNjZIUW5CRDltWm1ac2lWV0RBPSIsInIiOiJCQitxSUxabDBxekY3dDNRZ0Y1ZFhoSHZrNlRwanIraEswRUY0cUFYT0l1dzZDMkxlN3RoSFBPMUx6WW8xeFdjQVZtdnlveStsMVJsRlB0NEVtVE1jK2c9IiwiY3QiOiJGb3Z3dlNOV3Rac0UzUDYvT3pJOHJkOFdqV3RiWkluTlVaeU4wTzJCRFB5ZlN6ZHJ5OXJoWEU5b085NG5KcmNFL0R0bjMyaWtiQi81MlZ2VWtBWmhRdz09IiwiaXYiOiJjcDFHdkMyVUVIcDBnU0FhREtIVGV3PT0iLCJ0YWciOiJZUXV5YVdXczR3YkU3OVExRE52cXFrcGFyNlNzSmNhLzA3VlViamdnM21zPSJ9LHsidG9fZWNkaCI6IkJMTjNZaHdpZE44N1pJcGkyZ3h4VnRicVkxRHRuYVp0NFA4QWxscTJsY2h0dW83aVo2bHcyemExbU5rbUpBZXVSOEI5UytaQUFGMEZZbTdwT1JSNmphMD0iLCJyIjoiQkhVbkt3bEdtVFM4clVPcTAxdmdJVWpML3FzQUFiRlZYMEJxUE90bW0zZTlFamZMZ21ZU0I0dmF4a2hoR21JWHFpeUl0bk5sUDVyeUswcnF0SGMyUVNRPSIsImN0IjoiZElTV05UbWZlTkdYRW5sOXZCZVQwWDhMbkNheHVjU2RRWGdvTnd2L3ozZjNPZ3lSVmxVZFlLa0NHZWNCd00xTlV0N2FBcnQ4YWFYTnoyZG5MQlE1cnc9PSIsIml2IjoieUVEM1NuVUp5eEJUbm10dFYwbnlvUT09IiwidGFnIjoici9QRWk4cVdJZVowbm03RnRic3NKRU4zRnlrS1pvQm93MTVubC9nVnluOD0ifSx7InRvX2VjZGgiOiJCR1VMSFVRVFdQUU14TXBuNUZkMGs4aWZGQUgrRlMyajlIRlZaNThtUUY4b3diTkF0V1pXdjBkK2l5dnhoZUw2L3plalJPNiszWDdIS1ZybmJMUnY2bDA9IiwiciI6IkJCVmduMmd4MXFBL0xXYW9xTTNuRXhlbmFtSWJHRmVBMVhDaWM4Tm1ZSFBtK29qU0c4VXhiNE1iMzdjaVNmb2hZZEQ4bWhZNGtoMU0zVWw3WGdjWEwxMD0iLCJjdCI6IklrM2t4a1NhcytMN2hBUFBkRG56WmVrVWt2c0lpQlIvS3d1NlBuTGlnY0tGc0NCaU5JcEJNV01lRndabGpENTJGM2Z5cTl3a0dlRWlUTUx6SDFwM3R3PT0iLCJpdiI6IlJPS3duMjhxV25GcHNsYTFZS1UzS2c9PSIsInRhZyI6IjBqRVpBejQydHpsNFcwc1hXMnh1VHhURzNvN1FMeFhEcWR0QUVlSXEwejA9In1d",
  "rtag": "NPya4f8zQEYNNXqdOyXuWYV83gON9Qz7yBrDoEvkaQE=",
  "ct": "L1oOGR60bJlkWl7dnaU+Hw==",
  "iv": "JFFIWx2rNLUcoUS4DaeqWA==",
  "tag": "WzpA/2wxyfTY+7TlxPVfduf4iQ0UJVt83eVpJmWuYYE=",
  "sig": "MEYCIQCM+JAOtg79LzDVjgLTI9QynCvW5zpmbNaG5pd75VjzeQIhAKyOs1C6X2v29ZzV7X4vxOIWPLJvhTEZmMXLl434tIB7",
  "from_ecsig": "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEDKprbYJc/VeyARTyRwmifNzTv/nBPS7j05rRpmAbwey/v4Q25U9HtVchCyYuYX7C/o9fomqfvCuWxX1xOIRKfg=="
}
```

A succinct overview of the fields of an encrypted envelope object is as follows:
1. `recvs`: The `n` serialized ECIES instances.
1. `rtag`: The MAC for the `recvs` field.
1. `ct`: The ciphertext.
1. `iv`: The initialization vector of the symmetric cipher.
1. `tag`: The output of the KMAC function for the ciphertext.
1. `sig`: The digital signature as computed by the sender.
1. `from_ecsig`: The sender's EC public verification key.
<br>

>### decrypt(receiverECDHKeyPair, encEnvelope)
- #### **Description:** The group encryption function of this implementation.
- #### **receiverECDHKeyPair**:  An object with properties `publicKey` and `privateKey` that encompass the receiver's ECDH key pair.
- #### **encEnvelope**: An encrypted envelope object as is output by the `encrypt()` function.
- #### **Returns**:  An Object with two properties, i.e., `from`, which contains the EC public verification key of the sender, and `message`, which contains the message as a `Buffer` type.

This function should **always** be invoked in a `try-catch` block as it can throw exceptions for various reasons.

## Benchmark

A simple benchmark for this implementation is provided in the `bench/bench-ecies-ge-doa.js` file. You can tune the number of intended recipients and the size of the message by modifying the `msgRecipients` and `msgSize` variables at the beginning of the file. The output of this script is along the lines of:

```
Generating ECDH key pairs for 1000 recipients...
Recipient ECDH key pairs generated!
ECIES-GE-DOA Benchmark Inputs: 1000 message recipients, message_size = 100 bytes and 10 iterations per operation.
Encryption benchmark results: Average Time = 2.2890964148 (secs)
Decryption benchmark results: Average Time = 0.024935315899999998 (secs)
```
for `msgRecipients=1000` and `msgSize=100`, which was executed on a fairly resource-constrained VM.

# Note on Group Encryption

This note is addressed to the knowledgeable, or otherwise interested, reader. The usage of the term *group encryption* throughout this documentation deviates substantially from its formal definition, which was introduced in the seminal work of [Kiayias et al.](https://link.springer.com/chapter/10.1007/978-3-540-76900-2_11). In their work, group encryption is defined as the encryption analogue of a group signature which, put simply, entails that the intended recipients are completely concealed. Clearly, none of the implementations in this repository provide for this property and the authors acknowledge the term's misuse. However, for the intended users of this repository's implementations, i.e., developers, the author's were unable to come up with an alternative term that could provide an intuitive description of the provided primitive.

# Security Drawbacks

As stated previously, the implementations provided in this repository are based on the assumption that the sender of the message is **honest**, which has the following implications:

- The sender can encrypt different key buffers for each recipient. Clearly, this has important implications, some of which are as follows:

  - Potentially multiple recipients, which are chosen by the sender, will not be able to decrypt the message.
  - A recipient, whether he can decrypt the message or not, has no way of knowing whether any other recipient can decrypt the message.
  - The sender can choose, for each recipient, which of all the involved verifications during decryption will fail. From a security perspective, this is not important, however, it is a subtlety worth mentioning.
- The sender is not forced to encrypt the plaintext for all group members.
- The sender can break forward secrecy by computing an additional ECIES instance for, e.g., a past group member, or any entity to be more precise. However, this can be addressed if the application code of all recipients discards an envelope that contains, e.g., a public ECDH key that, on receipt, is not part of the group.

# To-Do List

- [ ] Explore and evaluate the degree in which operations can be parallelized.
- [ ] Expand the provided API to allow for optional callbacks.
