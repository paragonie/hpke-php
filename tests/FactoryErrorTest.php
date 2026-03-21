<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests;

use ParagonIE\HPKE\Factory;
use ParagonIE\HPKE\HPKEException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class FactoryErrorTest extends TestCase
{
    public static function invalidSuiteProvider(): array
    {
        return [
            'invalid pattern' => ['totally-invalid'],
            'empty string' => [''],
            'unknown KEM' => [
                'FOOKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM'
            ],
            'unknown AEAD' => [
                'DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, FooAEAD'
            ],
            'unknown KDF' => [
                'DHKEM(X25519, HKDF-SHA256), HKDF-BLAKE2b, AES-128-GCM'
            ],
            'unknown inner KDF' => [
                'DHKEM(X25519, HKDF-BLAKE2b), HKDF-SHA256, AES-128-GCM'
            ],
        ];
    }

    #[DataProvider('invalidSuiteProvider')]
    public function testInvalidSuiteThrows(string $input): void
    {
        $this->expectException(HPKEException::class);
        Factory::init($input);
    }

    public function testUnknownKdfMessage(): void
    {
        try {
            Factory::init(
                'DHKEM(X25519, HKDF-BLAKE2b), HKDF-SHA256, AES-128-GCM'
            );
            $this->fail('Expected HPKEException');
        } catch (HPKEException $e) {
            $this->assertStringStartsWith(
                'Unknown KDF: ',
                $e->getMessage()
            );
            $this->assertSame(
                'Unknown KDF: HKDF-BLAKE2b',
                $e->getMessage()
            );
        }
    }

    /**
     * @throws HPKEException
     */
    public function testHkdfSha384ViaFactory(): void
    {
        $hpke = Factory::init(
            'DHKEM(X25519, HKDF-SHA256), HKDF-SHA384, AES-128-GCM'
        );
        $this->assertSame(
            'DHKEM(X25519, HKDF-SHA256), HKDF-SHA384, AES-128-GCM',
            $hpke->getSuiteName()
        );
    }

    /**
     * @throws HPKEException
     */
    public function testChaCha20Poly1305AlternateName(): void
    {
        $hpke = Factory::init(
            'DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305'
        );
        $this->assertSame(
            'DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305',
            $hpke->getSuiteName()
        );
    }

    /**
     * @throws HPKEException
     */
    public function testGetKdfIsSubclassAccessible(): void
    {
        $kdf = TestableFactory::publicGetKDF('HKDF-SHA256');
        $this->assertSame('HKDF-SHA256', $kdf->getSuiteName());
    }

    /**
     * @throws HPKEException
     */
    public function testExportOnlyViaFactory(): void
    {
        $hpke = Factory::init(
            'DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, Export-Only AEAD'
        );
        $this->assertSame(
            'DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, Export-Only AEAD',
            $hpke->getSuiteName()
        );
    }
}
