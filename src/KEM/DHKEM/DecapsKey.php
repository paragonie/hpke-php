<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\KEM\DHKEM;

use Mdanter\Ecc\Crypto\Key\{
    PrivateKey,
    PrivateKeyInterface
};
use Mdanter\Ecc\Exception\InsecureCurveException;
use Mdanter\Ecc\Math\ConstantTimeMath;
use Mdanter\Ecc\Serializer\Point\UncompressedPointSerializer;
use ParagonIE\EasyECC\Curve25519\MontgomerySecretKey;
use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\Interfaces\DecapsKeyInterface;
use SodiumException;

class DecapsKey implements DecapsKeyInterface
{
    public function __construct(
        public readonly Curve $curve,
        #[\SensitiveParameter]
        public readonly string $bytes
    ){}

    /**
     * @throws HPKEException
     * @throws SodiumException
     * @throws InsecureCurveException
     */
    public function toPrivateKey(): PrivateKeyInterface
    {
        if ($this->curve === Curve::X25519) {
            return new MontgomerySecretKey($this->bytes);
        }
        return new PrivateKey(
            new ConstantTimeMath(),
            $this->curve->getGenerator(),
            gmp_init(sodium_bin2hex($this->bytes), 16)
        );
    }

    /**
     * @throws HPKEException
     * @throws InsecureCurveException
     * @throws SodiumException
     */
    public function getEncapsKey(): EncapsKey
    {
        if ($this->curve === Curve::X25519) {
            return new EncapsKey($this->curve, sodium_crypto_box_publickey_from_secretkey($this->bytes));
        }
        $publicPoint = $this->toPrivateKey()->getPublicKey()->getPoint();
        $serializer = new UncompressedPointSerializer();
        return new EncapsKey($this->curve, sodium_hex2bin($serializer->serialize($publicPoint)));
    }
}
