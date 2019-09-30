<?php

/**
 * Example using Halite
 */

$halite = new EncryptDemo\Halite();
$halite->createEncryptionKey();
$halite->createAuthenticationKey();

echo "------------ Halite encryption" . PHP_EOL;

$encrypted = $halite->encrypt("Attack at dawn");

// ... store the ciphertext in the database, we don't need to worry about nonce

$decrypted = $halite->decrypt($encrypted);

echo 'Decrypted: [' . $decrypted->getString() . ']' . PHP_EOL;

echo "------------ Halite password checking (extended functionality of timing safe comparison)" . PHP_EOL;

$hashForDatabase = $halite->hashAndEncryptPassword('passwords are better than passphrases');

$valid = $halite->isPasswordValid('C*mPl3xPasswordsRule!', $hashForDatabase);

$msg = $valid ? 'valid' : 'invalid';

echo 'The passphrase supplied passphrase is [' . $msg .']' . PHP_EOL;

echo "------------ Halite message authentication" . PHP_EOL;

$mac = $halite->getMac('attack at dawn');

// ... send mac and message over the network to a receiver who already knows the key

// check validity, in this example with a message that was tampered with
$messageIsValid = $halite->isMacValid($mac, "attack at dusk");

$outputMessage = $messageIsValid ? 'Message is authentic' : 'Opponent tampered with message';

echo $outputMessage . PHP_EOL;