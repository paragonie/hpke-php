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
