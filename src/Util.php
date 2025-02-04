<?php
declare(strict_types=1);
namespace ParagonIE\HPKE;

use GMP;
use SodiumException;

class Util
{
    /**
     * @throws SodiumException
     */
    public static function gmpToBytes(GMP $input, int $length): string
    {
        $unpadded = gmp_strval($input, 16);
        return sodium_hex2bin(str_pad(
            $unpadded,
            $length << 1,
            '0',
            STR_PAD_LEFT
        ));
    }

    /**
     * @throws SodiumException
     */
    public static function bytesToGmp(string $buf): GMP
    {
        return gmp_init(sodium_bin2hex($buf), 16);
    }
}
