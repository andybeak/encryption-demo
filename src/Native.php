<?php

namespace EncryptDemo;

class Native
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
    public function createEncryptionKey(): void
    {
        // use cryptographically safe function to generate randomness for key and nonce
        $key = random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
        file_put_contents(self::ENC_KEY_FILENAME, $key);
    }

    /**
     * Create a key for authentication and write to disk
     */
    public function createAuthKey(): void
    {
        $key = random_bytes(SODIUM_CRYPTO_AUTH_KEYBYTES);
        file_put_contents(self::AUTH_KEY_FILENAME, $key);
    }

    /**
     * Return an array containing ciphertext and the nonce used to encrypt
     *
     * @param string $message
     * @return array
     * @throws \Exception
     */
    public function encrypt(string $message): array
    {
        $key = file_get_contents(self::ENC_KEY_FILENAME);

        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        // encrypt
        $ciphertext = sodium_crypto_secretbox($message, $nonce, $key);

        // convert to safe ascii
        $ciphertext = sodium_bin2hex($ciphertext);

        // securely erase the contents of the original message
        sodium_memzero($message);

        // avoid leaving the key in memory (Heartbleed, for example, could leak it)
        sodium_memzero($key);

        return compact('ciphertext', 'nonce');
    }

    /**
     * Decrypt ciphertext being supplied with the nonce used to encrypt it
     * @param string $ciphertext
     * @param string $nonce
     * @return string
     * @throws \SodiumException
     */
    public function decrypt(string $ciphertext, string $nonce): string
    {
        $key = file_get_contents(self::ENC_KEY_FILENAME);

        return sodium_crypto_secretbox_open(sodium_hex2bin($ciphertext), $nonce, $key);
    }

    /**
     * @param string $stringA
     * @param string $stringB
     * @return bool
     * @throws \SodiumException
     */
    public function timingConstantStringComparison(string $stringA, string $stringB): bool
    {
        // Timing-safe variant of PHP's native strcmp(), see that function for documentation of sodium_compare
        return sodium_compare($stringA, $stringB) === 0;
    }

    /**
     * Generate a mac using the authentication key
     * @param string $message
     * @return string
     * @throws \SodiumException
     */
    public function getMac(string $message): string
    {
        $key = file_get_contents(self::AUTH_KEY_FILENAME);

        // calculate a signature for the message
        $mac = sodium_crypto_auth($message, $key);

        // securely erase the contents of the original message
        sodium_memzero($message);

        return $mac;
    }

    /**
     * Verify that the message is authentic by checking the mac with the key
     * @param string $mac
     * @param string $message
     * @return bool
     * @throws \SodiumException
     */
    public function isMacValid(string $mac, string $message): bool
    {
        $key = file_get_contents(self::AUTH_KEY_FILENAME);

        return sodium_crypto_auth_verify($mac, $message, $key);
    }
}