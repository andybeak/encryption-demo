<?php

require('vendor/autoload.php');

if (!function_exists('sodium_crypto_secretbox')) {
    exit('You should be running a supported version of PHP which has Sodium built in.');
}

require('native.php');
require('halite.php');