<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Interfaces;

use ParagonIE\HPKE\SymmetricKey;

interface AEADInterface
{
    public function getAeadId(): string;
    public function keyLength(): int;
    public function nonceLength(): int;
    public function tagLength(): int;

    public function encrypt(
        #[\SensitiveParameter]
        SymmetricKey $key,
        #[\SensitiveParameter]
        string $plaintext,
        string $nonce,
        string $aad = ''
    ): array;

    public function decrypt(
        #[\SensitiveParameter]
        SymmetricKey $key,
        string $ciphertext,
        string $tag,
        string $nonce,
        string $aad = ''
    ): string;
}
