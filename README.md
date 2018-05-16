# pskcrypto
PrivateSky module that collects crypto-related  stuff on the server side (node.js)



##APIs:

        var crypto = require("cryptography");

###Generate ECDSA key-pair in PEM format

        var keys = crypto.generateECDSAKeyPair();

###Sign and verify signatures

        var signature = crypto.sign(keys.private, 'some text');
        crypto.verify(keys.public, signature, 'some text');

###Generate encryption keys

        var encryptionKey = crypto.generateEncryptionKey();

###Generate initialization vector

        var iv = crypto.generateIV();

###Encrypt and decrypt text

        var cipherText = crypto.encrypt('some text', encryptionKey, iv);

        var plaintext = crypto.decrypt(cipherText, encryptionKey, iv);
