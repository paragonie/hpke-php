<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Interfaces;

interface KemInterface
{
    public function generateKeys(): array;

    public function getHeaderLength(): int;

    public function getKemId(): string;

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

    public function authEncaps(
        EncapsKeyInterface $encapsKey,
        DecapsKeyInterface $decapsKey
    ): array;

    public function authDecaps(
        DecapsKeyInterface $decapsKey,
        EncapsKeyInterface $encapsKey,
        string $enc
    ): SymmetricKeyInterface;
}
