<?php

namespace EncryptDemo;

use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\HiddenString;
use ParagonIE\Halite\Symmetric\Crypto as Symmetric;

class Halite
{
    /**
     * Mapping, to avoid going past column 80
     */
    const DS = DIRECTORY_SEPARATOR;

    /**
     * Filename to store the encryption key in
     */
    const ENC_KEY_FILENAME = __DIR__ . self::DS . '..' . self::DS . 'key' . self::DS . 'encryption.key';

    /**
     * Filename to store the authentication key in
     */
    const AUTH_KEY_FILENAME = __DIR__ . self::DS . '..' . self::DS . 'key' . self::DS . 'auth.key';

    /**
     * Create a key for encryption and write to disk
     */
    /**
     * @throws \ParagonIE\Halite\Alerts\CannotPerformOperation
     * @throws \ParagonIE\Halite\Alerts\InvalidKey
     */
    public function createEncryptionKey(): void
    {
        // note: no need to use the libsodium constant
        $encKey = KeyFactory::generateEncryptionKey();
        KeyFactory::save($encKey, self::ENC_KEY_FILENAME);
    }

    /**
     * Create a key for authentication and write to disk
     * @throws \ParagonIE\Halite\Alerts\CannotPerformOperation
     * @throws \ParagonIE\Halite\Alerts\InvalidKey
     */
    public function createAuthenticationKey(): void
    {
        $authKey = \ParagonIE\Halite\KeyFactory::generateAuthenticationKey();
        KeyFactory::save($authKey, self::AUTH_KEY_FILENAME);
    }

    /**
     * Encrypt a message and return the ciphertext.  Note that we don't need to worry about the nonce..
     *
     * @param string $message
     * @return string
     * @throws \ParagonIE\Halite\Alerts\CannotPerformOperation
     * @throws \ParagonIE\Halite\Alerts\InvalidDigestLength
     * @throws \ParagonIE\Halite\Alerts\InvalidKey
     * @throws \ParagonIE\Halite\Alerts\InvalidMessage
     * @throws \ParagonIE\Halite\Alerts\InvalidType
     */
    public function encrypt(string $message): string
    {
        $encryptionKey = KeyFactory::loadEncryptionKey(self::ENC_KEY_FILENAME);
        $hiddenString = new HiddenString($message);
        return Symmetric::encrypt($hiddenString, $encryptionKey);
    }

    /**
     * Decrypt the supplied ciphertext
     *
     * @param string $ciphertext
     * @return HiddenString
     * @throws \ParagonIE\Halite\Alerts\CannotPerformOperation
     * @throws \ParagonIE\Halite\Alerts\InvalidDigestLength
     * @throws \ParagonIE\Halite\Alerts\InvalidKey
     * @throws \ParagonIE\Halite\Alerts\InvalidMessage
     * @throws \ParagonIE\Halite\Alerts\InvalidSignature
     * @throws \ParagonIE\Halite\Alerts\InvalidType
     */
    public function decrypt(string $ciphertext): HiddenString
    {
        $encryptionKey = KeyFactory::loadEncryptionKey(self::ENC_KEY_FILENAME);
        return Symmetric::decrypt($ciphertext, $encryptionKey);
    }

    /**
     * You might want to encrypt the hash of the password if the network between your database and webserver
     * can't be trusted, or if you just want to defend in depth.
     * @param string $password
     * @return string
     * @throws \ParagonIE\Halite\Alerts\CannotPerformOperation
     * @throws \ParagonIE\Halite\Alerts\InvalidDigestLength
     * @throws \ParagonIE\Halite\Alerts\InvalidKey
     * @throws \ParagonIE\Halite\Alerts\InvalidMessage
     * @throws \ParagonIE\Halite\Alerts\InvalidType
     */
    public function hashAndEncryptPassword(string $passPhrase): string
    {
        $encryptionKey = KeyFactory::loadEncryptionKey(self::ENC_KEY_FILENAME);

        $hiddenString = new HiddenString($passPhrase);

        return \ParagonIE\Halite\Password::hash(
            $hiddenString,
            $encryptionKey
        );
    }

    /**
     * @param string $suppliedPassphrase
     * @param string $databaseHash
     * @return bool
     * @throws \ParagonIE\Halite\Alerts\CannotPerformOperation
     * @throws \ParagonIE\Halite\Alerts\InvalidDigestLength
     * @throws \ParagonIE\Halite\Alerts\InvalidKey
     * @throws \ParagonIE\Halite\Alerts\InvalidSignature
     * @throws \ParagonIE\Halite\Alerts\InvalidType
     */
    public function isPasswordValid(string $suppliedPassphrase, string $databaseHash)
    {
        $encryptionKey = KeyFactory::loadEncryptionKey(self::ENC_KEY_FILENAME);

        $hiddenString = new HiddenString($suppliedPassphrase);

        try {
            if (\ParagonIE\Halite\Password::verify(
                $hiddenString,
                $databaseHash,
                $encryptionKey
            )) {
                return true;
            }
        } catch (\ParagonIE\Halite\Alerts\InvalidMessage $ex) {
            return false;
        }
    }

    /**
     * Obtain a message authentication code for the message
     * @param string $message
     * @return string
     * @throws \ParagonIE\Halite\Alerts\CannotPerformOperation
     * @throws \ParagonIE\Halite\Alerts\InvalidKey
     * @throws \ParagonIE\Halite\Alerts\InvalidMessage
     * @throws \ParagonIE\Halite\Alerts\InvalidType
     */
    public function getMac(string $message): string
    {
        $authenticationKey = KeyFactory::loadAuthenticationKey(self::ENC_KEY_FILENAME);

        return \ParagonIE\Halite\Symmetric\Crypto::authenticate(
            $message,
            $authenticationKey
        );

    }

    /**
     * @param string $mac
     * @param string $message
     * @return bool
     * @throws \ParagonIE\Halite\Alerts\CannotPerformOperation
     * @throws \ParagonIE\Halite\Alerts\InvalidKey
     * @throws \ParagonIE\Halite\Alerts\InvalidMessage
     * @throws \ParagonIE\Halite\Alerts\InvalidSignature
     * @throws \ParagonIE\Halite\Alerts\InvalidType
     */
    public function isMacValid(string $mac, string $message): bool
    {
        $authenticationKey = KeyFactory::loadAuthenticationKey(self::ENC_KEY_FILENAME);

        return \ParagonIE\Halite\Symmetric\Crypto::verify(
            $message,
            $authenticationKey,
            $mac
        );
    }
}