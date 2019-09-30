<?php

/**
 * Example using native libsodium
 */

$native = new EncryptDemo\Native();
$native->createEncryptionKey();
$native->createAuthKey();

echo "------------ Native encryption" . PHP_EOL;

$encrypted = $native->encrypt("Attack at dawn");

// ... store $encrypted['ciphertext'] and $encrypted['nonce'] in the database, we will need them both when we decrypt

$decrypted = $native->decrypt($encrypted['ciphertext'], $encrypted['nonce']);

echo 'Decrypted: [' . $decrypted . ']' . PHP_EOL;

echo "------------ Native constant-time string comparison" . PHP_EOL;

$match = $native->timingConstantStringComparison("attack at dawn", "attack at dusk");

$outputMessage =  $match ? "Strings match" : "Strings don't match";

echo $outputMessage . PHP_EOL;

echo "------------ Native message authentication" . PHP_EOL;

$mac = $native->getMac("attack at dawn");

// ... send mac and message over the network to a receiver who already knows the key

// check validity, in this example with a message that was tampered with
$messageIsValid = $native->isMacValid($mac, "attack at dusk");

$outputMessage = $messageIsValid ? 'Message is authentic' : 'Opponent tampered with message';

echo $outputMessage . PHP_EOL;
