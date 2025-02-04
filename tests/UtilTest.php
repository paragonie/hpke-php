<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests;

use ParagonIE\HPKE\Util;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(Util::class)]
class UtilTest extends TestCase
{
    public static function conversionProvider(): array
    {
        return [
            'zeroes' => [str_repeat("\0", 8)],
            '8 random bytes' => [random_bytes(8)]
        ];
    }

    #[DataProvider('conversionProvider')]
    public function testConversion(string $input): void
    {
        $length = strlen($input);
        $gmp = Util::bytesToGmp($input);
        $back = Util::gmpToBytes($gmp, $length);
        $this->assertSame($back, $input);
    }
}
