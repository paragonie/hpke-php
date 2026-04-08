<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\KEM;

use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\SymmetricKey;
use ParagonIE\HPKE\Interfaces\{
    DecapsKeyInterface,
    EncapsKeyInterface,
    KemInterface,
    SymmetricKeyInterface
};
use ParagonIE\HPKE\KEM\PQKEM\{
    Algorithm,
    DecapsKey,
    EncapsKey
};
use ParagonIE\PQCrypto\Compat;
use ParagonIE\PQCrypto\Exception\{
    MLKemInternalException,
    PQCryptoCompatException
};
use Random\RandomException;
use SodiumException;
use TypeError;

class PostQuantumKEM implements KemInterface
{
    public function __construct(public readonly Algorithm $algorithm)
    {}

    public function getPublicKeyLength(): int
    {
        return $this->algorithm->encapsKeyLength();
    }

    public function getSecretLength(): int
    {
        return $this->algorithm->secretLength();
    }

    public function getSecretKeyLength(): int
    {
        return $this->algorithm->decapsKeyLength();
    }

    /**
     * Nenc: ciphertext length for the KEM.
     */
    public function getHeaderLength(): int
    {
        return $this->algorithm->ciphertextLength();
    }

    public function getKemId(): string
    {
        return $this->algorithm->kemId();
    }

    public function getSuiteName(): string
    {
        return $this->algorithm->value;
    }

    /**
     * @return array{0: DecapsKeyInterface, 1: EncapsKeyInterface}
     *
     * @throws HPKEException
     * @throws MLKemInternalException
     * @throws RandomException
     * @throws SodiumException
     */
    public function generateKeys(): array
    {
        [$dk, $ek] = match ($this->algorithm) {
            Algorithm::MLKem768 => Compat::mlkem768_keygen(),
            Algorithm::MLKem1024 => Compat::mlkem1024_keygen(),
            Algorithm::XWing => Compat::xwing_keygen(),
        };
        return [
            new DecapsKey($this->algorithm, $dk->bytes()),
            new EncapsKey($this->algorithm, $ek->bytes()),
        ];
    }

    /**
     * @return array{0: SymmetricKeyInterface, 1: string}
     *
     * @throws HPKEException
     * @throws MLKemInternalException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    public function encapsulate(EncapsKeyInterface $encapsKey): array
    {
        if (!$encapsKey instanceof EncapsKey) {
            throw new TypeError('Expected PQ encapsulation key');
        }
        if ($encapsKey->algorithm !== $this->algorithm) {
            throw new HPKEException('Encapsulation key algorithm mismatch');
        }
        $result = match ($this->algorithm) {
            Algorithm::MLKem768 =>
                Compat::mlkem768_encaps($encapsKey->bytes),
            Algorithm::MLKem1024 =>
                Compat::mlkem1024_encaps($encapsKey->bytes),
            Algorithm::XWing =>
                Compat::xwing_encaps($encapsKey->bytes),
        };
        return [
            new SymmetricKey($result['sharedKey']),
            $result['ciphertext'],
        ];
    }

    /**
     * @throws HPKEException
     * @throws MLKemInternalException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    public function decapsulate(
        DecapsKeyInterface $decapsKey,
        string $enc
    ): SymmetricKeyInterface {
        if (!$decapsKey instanceof DecapsKey) {
            throw new HPKEException('Expected PQ decapsulation key');
        }
        if ($decapsKey->algorithm !== $this->algorithm) {
            throw new HPKEException('Decapsulation key algorithm mismatch');
        }
        $sharedSecret = match ($this->algorithm) {
            Algorithm::MLKem768 =>
                Compat::mlkem768_decaps($decapsKey->bytes, $enc),
            Algorithm::MLKem1024 =>
                Compat::mlkem1024_decaps($decapsKey->bytes, $enc),
            Algorithm::XWing =>
                Compat::xwing_decaps($decapsKey->bytes, $enc),
            default => throw new HPKEException('Unknown algorithm'),
        };
        return new SymmetricKey($sharedSecret);
    }

    /**
     * PQ KEMs don't need the HPKE reference (no ExtractAndExpand)
     */
    public function withHPKE(HPKE $hpke): static
    {
        return $this;
    }
}
