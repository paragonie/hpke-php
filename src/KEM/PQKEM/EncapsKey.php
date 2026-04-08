<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\KEM\PQKEM;

use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\Interfaces\EncapsKeyInterface;

class EncapsKey implements EncapsKeyInterface
{
    /**
     * @throws HPKEException
     */
    public function __construct(
        public readonly Algorithm $algorithm,
        #[\SensitiveParameter]
        public readonly string $bytes
    ) {
        $expected = $this->algorithm->encapsKeyLength();
        if (strlen($this->bytes) !== $expected) {
            throw new HPKEException(
                "Invalid public key length for {$this->algorithm->value}"
            );
        }
    }
}
