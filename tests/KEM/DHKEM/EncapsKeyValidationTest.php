<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests\KEM\DHKEM;

use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\KEM\DHKEM\Curve;
use ParagonIE\HPKE\KEM\DHKEM\EncapsKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class EncapsKeyValidationTest extends TestCase
{
    public static function invalidLengthProvider(): array
    {
        return [
            'X25519 too short' => [
                Curve::X25519,
                str_repeat("\x42", 31),
            ],
            'X25519 too long' => [
                Curve::X25519,
                str_repeat("\x42", 33),
            ],
            'P-256 too short' => [
                Curve::NistP256,
                str_repeat("\x42", 64),
            ],
            'P-256 too long' => [
                Curve::NistP256,
                str_repeat("\x42", 66),
            ],
        ];
    }

    #[DataProvider('invalidLengthProvider')]
    public function testInvalidKeyLength(Curve $curve, string $bytes): void
    {
        $this->expectException(HPKEException::class);
        $this->expectExceptionMessage('Invalid public key length');
        new EncapsKey($curve, $bytes);
    }

    public function testValidKeyLengthAccepted(): void
    {
        // X25519: 32 bytes, not the generator
        $key = new EncapsKey(
            Curve::X25519,
            str_repeat("\x42", 32)
        );
        $this->assertSame(32, strlen($key->bytes));
    }
}
