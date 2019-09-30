# Encryption in PHP

As of PHP 7.2.0 the [Sodium library](https://www.php.net/manual/en/book.sodium.php) is bundled with PHP.  The PHP library  is built on [Libsodium](https://libsodium.gitbook.io/doc/).  Sodium is a modern, easy-to-use software library for encryption, decryption, signatures, password hashing and more.

This simple demo shows how to encrypt and decrypt data as well as create a message authentication code (mac). 

It uses native Sodium calls and shows equivalent calls using [Halite](https://github.com/paragonie/halite)
by [Paragon Initiative Enterprises](https://paragonie.com/).  Halite offers a number of convenient wrappers to make it easier and 
more intuitive to perform common functions. 

See also [envelope encryption](https://github.com/andybeak/envelope-encryption).

## Running the program

This program requires that Sodium is available.  It is bundled with PHP 7.2.0 and above, but otherwise must be installed with PECL. At time of writing the oldest supported version of PHP is 7.2.0 (see [here](https://www.php.net/supported-versions.php) for the currently supported PHP versions).

To run the program:

    php index.php
    
Example output:

    ------------ Native encryption
    Decrypted: [Attack at dawn]
    ------------ Native constant-time string comparison
    Strings don't match
    ------------ Native message authentication
    Opponent tampered with message
    ------------ Halite encryption
    Decrypted: [Attack at dawn]
    ------------ Halite password checking (extended functionality of timing safe comparison)
    The passphrase supplied passphrase is [invalid]
    ------------ Halite message authentication
    Opponent tampered with message


