<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests\KEM\DHKEM;

use Mdanter\Ecc\Serializer\Point\UncompressedPointSerializer;
use ParagonIE\HPKE\KEM\DHKEM\Curve;
use ParagonIE\HPKE\KEM\DHKEM\EncapsKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(EncapsKey::class)]
class EncapsKeyTest extends TestCase
{
    public function testRejectsGeneratorX25519(): void
    {
        // Generator for X25519 is 9.
        $bytes = str_repeat("\x00", 32);
        $bytes[0] = "\x09";

        // This should throw an exception if we are rejecting the generator
        $this->expectException(\Exception::class);
        new EncapsKey(Curve::X25519, $bytes);
    }

    public function testRejectsGeneratorNistP256(): void
    {
        $curve = Curve::NistP256;
        $generator = $curve->getGenerator();
        $serializer = new UncompressedPointSerializer();
        $bytes = hex2bin($serializer->serialize($generator));

        $this->expectException(\Exception::class);
        new EncapsKey($curve, $bytes);
    }

    public function testRejectsGeneratorSecp256k1(): void
    {
        $curve = Curve::Secp256k1;
        $generator = $curve->getGenerator();
        $serializer = new UncompressedPointSerializer();
        $bytes = hex2bin($serializer->serialize($generator));

        $this->expectException(\Exception::class);
        new EncapsKey($curve, $bytes);
    }

    public function testRejectsGeneratorNistP384(): void
    {
        $curve = Curve::NistP384;
        $generator = $curve->getGenerator();
        $serializer = new UncompressedPointSerializer();
        $bytes = hex2bin($serializer->serialize($generator));

        $this->expectException(\Exception::class);
        new EncapsKey($curve, $bytes);
    }

    public function testRejectsGeneratorNistP521(): void
    {
        $curve = Curve::NistP521;
        $generator = $curve->getGenerator();
        $serializer = new UncompressedPointSerializer();
        $bytes = hex2bin($serializer->serialize($generator));

        $this->expectException(\Exception::class);
        new EncapsKey($curve, $bytes);
    }
}
