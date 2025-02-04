<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\AEAD;

use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\Interfaces\AEADInterface;
use ParagonIE\HPKE\SymmetricKey;

class AES256GCM implements AEADInterface
{
    const AEAD_ID = "\x00\x02";

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


    public function encrypt(
        #[\SensitiveParameter] SymmetricKey $key,
        #[\SensitiveParameter] string $plaintext,
        string $nonce,
        string $aad = ''
    ): array {
        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            $key->bytes,
            OPENSSL_RAW_DATA | OPENSSL_NO_PADDING,
            $nonce,
            $tag,
            $aad
        );
        return [$ciphertext, $tag];
    }

    /**
     * @throws HPKEException
     */
    public function decrypt(
        #[\SensitiveParameter] SymmetricKey $key,
        string $ciphertext,
        string $tag,
        string $nonce,
        string $aad = ''
    ): string {
        $result = openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            $key->bytes,
            OPENSSL_RAW_DATA | OPENSSL_NO_PADDING,
            $nonce,
            $tag,
            $aad
        );
        if (!is_string($result)) {
            throw new HPKEException('Decryption error');
        }
        return $result;
    }
}
