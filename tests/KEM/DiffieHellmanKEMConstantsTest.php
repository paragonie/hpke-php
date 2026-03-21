<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests\KEM;

use ParagonIE\HPKE\Hash;
use ParagonIE\HPKE\KDF\HKDF;
use ParagonIE\HPKE\KEM\DHKEM\Curve;
use ParagonIE\HPKE\KEM\DiffieHellmanKEM;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class DiffieHellmanKEMConstantsTest extends TestCase
{
    public static function curveConstantsProvider(): array
    {
        return [
            'X25519' => [
                Curve::X25519,
                Hash::Sha256,
                32,  // publicKeyLength
                32,  // secretLength
                32,  // secretKeyLength
                32,  // headerLength
                "\x00\x20", // kemId
                'KEM' . "\x00\x20", // suiteId
            ],
            'P-256' => [
                Curve::NistP256,
                Hash::Sha256,
                65,
                32,
                32,
                65,
                "\x00\x10",
                'KEM' . "\x00\x10",
            ],
            'P-384' => [
                Curve::NistP384,
                Hash::Sha384,
                97,
                48,
                48,
                97,
                "\x00\x11",
                'KEM' . "\x00\x11",
            ],
            'P-521' => [
                Curve::NistP521,
                Hash::Sha512,
                133,
                64,
                66,
                133,
                "\x00\x12",
                'KEM' . "\x00\x12",
            ],
            'secp256k1' => [
                Curve::Secp256k1,
                Hash::Sha256,
                65,
                32,
                32,
                65,
                "\x00\x16",
                'KEM' . "\x00\x16",
            ],
        ];
    }

    #[DataProvider('curveConstantsProvider')]
    public function testConstants(
        Curve $curve,
        Hash $hash,
        int $publicKeyLength,
        int $secretLength,
        int $secretKeyLength,
        int $headerLength,
        string $kemId,
        string $suiteId,
    ): void {
        $kem = new DiffieHellmanKEM($curve, new HKDF($hash));

        $this->assertSame(
            $publicKeyLength,
            $kem->getPublicKeyLength(),
            'Public key length'
        );
        $this->assertSame(
            $secretLength,
            $kem->getSecretLength(),
            'Secret length'
        );
        $this->assertSame(
            $secretKeyLength,
            $kem->getSecretKeyLength(),
            'Secret key length'
        );
        $this->assertSame(
            $headerLength,
            $kem->getHeaderLength(),
            'Header length'
        );
        $this->assertSame(
            bin2hex($kemId),
            bin2hex($kem->getKemId()),
            'KEM ID'
        );
        $this->assertSame(
            bin2hex($suiteId),
            bin2hex($kem->getSuiteId()),
            'Suite ID'
        );
    }
}
