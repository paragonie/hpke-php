<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests;

use ParagonIE\HPKE\Factory;
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\HPKEException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SodiumException;

#[CoversClass(Factory::class)]
class FactoryTest extends TestCase
{
    public static function factoryProvider(): array
    {
        return [
            [
                Factory::dhkem_x25519sha256_hkdf_sha256_aes128gcm(),
                'DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM',
                "HPKE\x00\x20\x00\x01\x00\x01"
            ],
            [
                Factory::dhkem_x25519sha256_hkdf_sha256_chacha20poly1305(),
                'DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305',
                "HPKE\x00\x20\x00\x01\x00\x03"
            ],
            [
                Factory::dhkem_p256sha256_hkdf_sha256_aes128gcm(),
                'DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM',
                "HPKE\x00\x10\x00\x01\x00\x01"
            ],
            [
                Factory::dhkem_p256sha256_hkdf_sha512_aes128gcm(),
                'DHKEM(P-256, HKDF-SHA256), HKDF-SHA512, AES-128-GCM',
                "HPKE\x00\x10\x00\x03\x00\x01"
            ],
            [
                Factory::dhkem_p256sha256_hkdf_sha256_chacha20poly1305(),
                'DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305',
                "HPKE\x00\x10\x00\x01\x00\x03"
            ],
            [
                Factory::dhkem_p521sha512_hkdf_sha512_aes256gcm(),
                'DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM',
                "HPKE\x00\x12\x00\x03\x00\x02"
            ],
            [
                Factory::dhkem_x25519sha256_hkdf_sha256_exportonly(),
                'DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, Export-Only AEAD',
                "HPKE\x00\x20\x00\x01\xFF\xFF"
            ]
        ];
    }

    /**
     * @throws HPKEException
     * @throws SodiumException
     */
    #[DataProvider('factoryProvider')]
    public function testFactory(HPKE $expect, string $suiteName, string $suiteId): void
    {
        $hpke = Factory::init($suiteName);
        $this->assertSame(
            sodium_bin2hex($suiteId),
            sodium_bin2hex($hpke->getSuiteId())
        );
        $this->assertSame(
            sodium_bin2hex($expect->getSuiteId()),
            sodium_bin2hex($hpke->getSuiteId())
        );
    }
}
