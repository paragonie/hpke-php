<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests;

use ParagonIE\HPKE\Hash;
use ParagonIE\HPKE\KDF\HKDF;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class HashEnumTest extends TestCase
{
    public static function hashProvider(): array
    {
        return [
            'SHA256' => [Hash::Sha256, 'SHA256', "\x00\x01"],
            'SHA384' => [Hash::Sha384, 'SHA384', "\x00\x02"],
            'SHA512' => [Hash::Sha512, 'SHA512', "\x00\x03"],
        ];
    }

    #[DataProvider('hashProvider')]
    public function testHashSuiteName(
        Hash $hash,
        string $suiteName,
        string $kdfId,
    ): void {
        $this->assertSame($suiteName, $hash->getSuiteName());

        $hkdf = new HKDF($hash);
        $this->assertSame(
            bin2hex($kdfId),
            bin2hex($hkdf->getKdfId()),
            'KDF ID for ' . $suiteName
        );
    }
}
