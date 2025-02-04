# Hybrid Public-Key Encryption (HPKE, RFC 9180) for PHP

[![Build Status](https://github.com/paragonie/hpke-php/actions/workflows/test.yml/badge.svg)](https://github.com/paragonie/hpke-php/actions)
[![Latest Stable Version](https://poser.pugx.org/paragonie/hpke/v/stable)](https://packagist.org/packages/paragonie/hpke)
[![Total Downloads](https://poser.pugx.org/paragonie/hpke/downloads)](https://packagist.org/packages/paragonie/hpke)
[![Latest Unstable Version](https://poser.pugx.org/paragonie/hpke/v/unstable)](https://packagist.org/packages/paragonie/hpke)
[![License](https://poser.pugx.org/paragonie/hpke/license)](https://packagist.org/packages/paragonie/hpke)

## Installation

```terminal
composer require paragonie/hpke
```

## Usage

### Instantiating HPKE

First, you need to decide on an HPKE ciphersuite. You can build these yourself by component, or use the standard modes
that ship with [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html#name-iana-considerations):

* DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
* DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305
* DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
* DHKEM(P-256, HKDF-SHA256), HKDF-SHA512, AES-128-GCM
* DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305
* DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM

To instantiate one of these ciphersuites, you can use the Factory class, like so:
```php
<?php
use ParagonIE\HPKE\Factory;

// Either approach will work fine.
$ciphersuite = Factory::init('DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM');
$otherCS = Factory::dhkem_p256sha256_hkdf_sha256_chacha20poly1305();
```

### Generating and Managing Key Pairs

Once you've instantiated your ciphersuite, you can now use it to generate/load keys.

```php
<?php
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\KEM\DHKEM\{DecapsKey, EncapsKey};
use Mdanter\Ecc\Serializer\{
    PublicKey\PemPublicKeySerializer,
    PrivateKey\PemPrivateKeySerializer
};

/** @var HPKE $hpke */

/**
 * @var EncapsKey $public
 * @var DecapsKey $secret
 */
[$secret, $public] = $hpke->kem->generateKeys();

// You can now use Easy-ECC or PHP-ECC to manage these keys:
$decapsulationKeyToSaveToDisk = (new PemPrivateKeySerializer())
    ->serialize($secret->toPrivateKey());

$encapsKeySharePublicly = (new PemPublicKeySerializer())
    ->serialize($public->toPublicKey());
```

### Setting Up Encryption Contexts

To set up an encryption context, simply use the `setupBaseSender()` and `setupBaseReceiver()`
APIs.

```php
<?php
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\KEM\DHKEM\{DecapsKey, EncapsKey};

/** 
 * @var HPKE $hpke 
 * @var EncapsKey $public
 * @var DecapsKey $secret
 */
 
const INFO = 'my custom protocol name';

// On one side
[$enc, $sender] = $hpke->setupBaseSender($public, INFO);

// On te other
$receiver = $hpke->setupBaseReceiver($secret, $enc, INFO);

// And now you can encrypt/decrypt:
$encrypted1 = $sender->seal('test message', 'first message AAD');
$decrypted1 = $receiver->open($encrypted1, 'first message AAD');

// The sequence is advanced automatically by our API
```

### One-Shot Encryption API

```php
<?php
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\KEM\DHKEM\{DecapsKey, EncapsKey};

/** 
 * @var HPKE $hpke 
 * @var EncapsKey $public
 * @var DecapsKey $secret
 */
 
const INFO = 'my custom protocol name';

// Sending (encryption)
$sealed = $hpke->sealBase($public, 'plaintext message', 'aad', INFO);

// Receiving (decryption)
$opened = $hpke->openBase($secret, $sealed, 'aad', INFO);
```
