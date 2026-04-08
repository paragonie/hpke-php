<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\KEM\PQKEM;

use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\Interfaces\DecapsKeyInterface;

class DecapsKey implements DecapsKeyInterface
{
    /**
     * @throws HPKEException
     */
    public function __construct(
        public readonly Algorithm $algorithm,
        #[\SensitiveParameter]
        public readonly string $bytes
    ) {
        $expected = $this->algorithm->decapsKeyLength();
        if (strlen($this->bytes) !== $expected) {
            throw new HPKEException(
                "Invalid secret key length for {$this->algorithm->value}"
            );
        }
    }
}
