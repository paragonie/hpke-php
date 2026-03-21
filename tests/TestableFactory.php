<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests;

use ParagonIE\HPKE\Factory;
use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\Interfaces\KDFInterface;

class TestableFactory extends Factory
{
    /**
     * @param string $name
     * @return KDFInterface
     * @throws HPKEException
     */
    public static function publicGetKDF(string $name): KDFInterface
    {
        return self::getKDF($name);
    }
}