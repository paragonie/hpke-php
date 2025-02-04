<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Interfaces;

interface KDFInterface
{
    public function getKdfId(): string;
    public function getHashLength(): int;

    public function deriveBytes(
        #[\SensitiveParameter]
        string|SymmetricKeyInterface $ikm,
        #[\SensitiveParameter]
        string $info = '',
        #[\SensitiveParameter]
        string $salt = ''
    ): string;

    public function deriveSymmetricKey(
        #[\SensitiveParameter]
        string|SymmetricKeyInterface $ikm,
        #[\SensitiveParameter]
        string $info = '',
        #[\SensitiveParameter]
        string $salt = ''
    ): SymmetricKeyInterface;

    public function extract(
        #[\SensitiveParameter]
        string|SymmetricKeyInterface $ikm,
        #[\SensitiveParameter]
        ?string $salt = null
    ): string;

    public function expand(
        #[\SensitiveParameter]
        string|SymmetricKeyInterface $prk,
        #[\SensitiveParameter]
        string $info,
        #[\SensitiveParameter]
        int $length
    ): string;
}
