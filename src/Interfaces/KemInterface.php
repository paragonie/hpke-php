<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Interfaces;

interface KemInterface
{
    public function generateKeys(): array;

    public function getHeaderLength(): int;

    public function getKemId(): string;
    public function getSuiteName(): string;

    public function getPublicKeyLength(): int;

    public function getSecretLength(): int;

    public function getSecretKeyLength(): int;

    public function encapsulate(
        EncapsKeyInterface $encapsKey
    ): array;

    public function decapsulate(
        DecapsKeyInterface $decapsKey,
        string $enc
    ): SymmetricKeyInterface;
}
