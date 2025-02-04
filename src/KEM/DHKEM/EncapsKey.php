<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\KEM\DHKEM;

use Mdanter\Ecc\Crypto\Key\{
    PublicKey,
    PublicKeyInterface
};
use Mdanter\Ecc\Exception\InsecureCurveException;
use Mdanter\Ecc\Math\ConstantTimeMath;
use Mdanter\Ecc\Primitives\PointInterface;
use Mdanter\Ecc\Serializer\Point\UncompressedPointSerializer;
use ParagonIE\EasyECC\Curve25519\MontgomeryPublicKey;
use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\Interfaces\EncapsKeyInterface;
use SodiumException;

class EncapsKey implements EncapsKeyInterface
{
    /**
     * @throws HPKEException
     */
    public function __construct(
        public readonly Curve $curve,
        #[\SensitiveParameter]
        public readonly string $bytes
    ){
        if (strlen($this->bytes) !== $this->curve->encapsKeyLength()) {
            throw new HPKEException('Invalid public key length');
        }
    }

    /**
     * @throws HPKEException
     * @throws InsecureCurveException
     * @throws SodiumException
     */
    public function toPublicKey(): PublicKeyInterface
    {
        if ($this->curve === Curve::X25519) {
            return new MontgomeryPublicKey($this->bytes);
        }
        return new PublicKey(
            new ConstantTimeMath(),
            $this->curve->getGenerator(),
            $this->getPoint()
        );
    }

    /**
     * @throws HPKEException
     * @throws InsecureCurveException
     * @throws SodiumException
     */
    public function getPoint(): PointInterface
    {
        if ($this->curve === Curve::X25519) {
            throw new HPKEException('Calling getPoint() on X25519 is unexpected');
        }
        $serializer = new UncompressedPointSerializer();
        return $serializer->unserialize($this->curve->getCurveFp(), sodium_bin2hex($this->bytes));
    }

    /**
     * @throws HPKEException
     * @throws InsecureCurveException
     * @throws SodiumException
     */
    public function serializeForHeader(): string
    {
        if ($this->curve === Curve::X25519) {
            return $this->bytes;
        }
        $serializer = new UncompressedPointSerializer();
        return sodium_hex2bin($serializer->serialize($this->getPoint()));
    }
}
