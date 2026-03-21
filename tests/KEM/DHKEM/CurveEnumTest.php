<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests\KEM\DHKEM;

use ParagonIE\HPKE\KEM\DHKEM\Curve;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class CurveEnumTest extends TestCase
{
    public static function curveEnumProvider(): array
    {
        return [
            'X25519' => [
                Curve::X25519,
                32,  // decapsKeyLength
                32,  // encapsKeyLength
                'X25519',  // suiteName
            ],
            'P-256' => [
                Curve::NistP256,
                32,
                65,
                'P-256',
            ],
            'P-384' => [
                Curve::NistP384,
                48,
                97,
                'P-384',
            ],
            'P-521' => [
                Curve::NistP521,
                66,
                133,
                'P-521',
            ],
            'secp256k1' => [
                Curve::Secp256k1,
                32,
                65,
                'secp256k1',
            ],
        ];
    }

    #[DataProvider('curveEnumProvider')]
    public function testCurveProperties(
        Curve $curve,
        int $decapsLen,
        int $encapsLen,
        string $suiteName,
    ): void {
        $this->assertSame($decapsLen, $curve->decapsKeyLength());
        $this->assertSame($encapsLen, $curve->encapsKeyLength());
        $this->assertSame($suiteName, $curve->getSuiteName());
    }

    /**
     * Verifies that getEasyECC() returns a valid EasyECC instance
     * for each curve.
     */
    #[DataProvider('curveEnumProvider')]
    public function testGetEasyECC(
        Curve $curve,
        int $decapsLen,
        int $encapsLen,
        string $suiteName,
    ): void {
        $ecc = $curve->getEasyECC();
        $this->assertInstanceOf(
            \ParagonIE\EasyECC\EasyECC::class,
            $ecc
        );
    }

    /**
     * X25519 generator bytes should be 9 followed by 31 zero bytes.
     */
    public function testX25519GeneratorBytes(): void
    {
        $gen = Curve::X25519->getGeneratorBytes();
        $this->assertSame(32, strlen($gen));
        $this->assertSame(
            "\x09" . str_repeat("\x00", 31),
            $gen
        );
    }

    /**
     * NIST curve generator bytes should have the correct length.
     */
    public function testNistP256GeneratorBytes(): void
    {
        $gen = Curve::NistP256->getGeneratorBytes();
        $this->assertSame(65, strlen($gen));
        // Uncompressed point starts with 0x04
        $this->assertSame("\x04", $gen[0]);
    }

    public function testNistP384GeneratorBytes(): void
    {
        $gen = Curve::NistP384->getGeneratorBytes();
        $this->assertSame(97, strlen($gen));
        $this->assertSame("\x04", $gen[0]);
    }

    public function testNistP521GeneratorBytes(): void
    {
        $gen = Curve::NistP521->getGeneratorBytes();
        $this->assertSame(133, strlen($gen));
        $this->assertSame("\x04", $gen[0]);
    }

    public function testSecp256k1GeneratorBytes(): void
    {
        $gen = Curve::Secp256k1->getGeneratorBytes();
        $this->assertSame(65, strlen($gen));
        $this->assertSame("\x04", $gen[0]);
    }
}
