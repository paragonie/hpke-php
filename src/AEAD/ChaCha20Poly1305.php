<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\AEAD;

use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\Interfaces\AEADInterface;
use ParagonIE\HPKE\SymmetricKey;
use SodiumException;

class ChaCha20Poly1305 implements AEADInterface
{
    const AEAD_ID = "\x00\x03";

    public function getAeadId(): string
    {
        return self::AEAD_ID;
    }

    public function keyLength(): int
    {
        return 32;
    }

    public function nonceLength(): int
    {
        return 12;
    }

    public function tagLength(): int
    {
        return 16;
    }


    /**
     * @throws SodiumException
     */
    public function encrypt(
        #[\SensitiveParameter] SymmetricKey $key,
        #[\SensitiveParameter] string $plaintext,
        string $nonce,
        string $aad = ''
    ): array {
        $output = sodium_crypto_aead_chacha20poly1305_ietf_encrypt(
            $plaintext,
            $aad,
            $nonce,
            $key->bytes
        );
        $ciphertext = substr($output, 0, -SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES);
        $tag = substr($output, -SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES);
        return [$ciphertext, $tag];
    }

    /**
     * @throws HPKEException
     * @throws SodiumException
     */
    public function decrypt(
        #[\SensitiveParameter] SymmetricKey $key,
        string $ciphertext,
        string $tag,
        string $nonce,
        string $aad = ''
    ): string {
        $result = sodium_crypto_aead_chacha20poly1305_ietf_decrypt(
            $ciphertext . $tag,
            $aad,
            $nonce,
            $key->bytes
        );
        if (!is_string($result)) {
            throw new HPKEException('Decryption error');
        }
        return $result;
    }
}
