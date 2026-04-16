<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\KEM\PQKEM;

use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\Interfaces\DecapsKeyInterface;
use ParagonIE\PQCrypto\Compat;
use ParagonIE\PQCrypto\Exception\MLKemInternalException;
use ParagonIE\PQCrypto\Exception\PQCryptoCompatException;
use SodiumException;

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

    /**
     * @throws HPKEException
     * @throws MLKemInternalException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    public function getEncapsKey(): EncapsKey
    {
        [, $encapsKey] = match($this->algorithm) {
            Algorithm::XWing => Compat::xwing_seed_keypair($this->bytes),
            Algorithm::MLKem768 => Compat::mlkem768_seed_keypair($this->bytes),
            Algorithm::MLKem1024 => Compat::mlkem1024_seed_keypair($this->bytes),
        };
        return new EncapsKey($this->algorithm, $encapsKey->bytes());
    }
}
