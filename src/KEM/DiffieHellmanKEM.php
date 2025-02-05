<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\KEM;

use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Exception\InsecureCurveException;
use Mdanter\Ecc\Serializer\Point\UncompressedPointSerializer;
use ParagonIE\EasyECC\EasyECC;
use ParagonIE\EasyECC\Exception\NotImplementedException;
use ParagonIE\HPKE\{
    HPKE,
    HPKEException,
    SymmetricKey,
    Util
};
use ParagonIE\HPKE\Interfaces\{
    DecapsKeyInterface,
    EncapsKeyInterface,
    KDFInterface,
    KemInterface,
    SymmetricKeyInterface
};
use ParagonIE\HPKE\KEM\DHKEM\{
    Curve,
    DecapsKey,
    EncapsKey
};
use SodiumException;
use TypeError;

class DiffieHellmanKEM implements KemInterface
{
    protected ?HPKE $hpke = null;

    public function __construct(
        public readonly Curve $curve,
        public readonly KDFInterface $kdf,
    ) {}

    /**
     * This is called Npk in the HPKE spec..
     *
     * @return int
     */
    public function getPublicKeyLength(): int
    {
        return match ($this->curve) {
            Curve::Secp256k1, Curve::NistP256 => 65,
            Curve::NistP384 => 97,
            Curve::NistP521 => 133,
            Curve::X25519 => 32
        };
    }

    /**
     * Thisi s called Nsec in the HPKE spec.
     */
    public function getSecretLength(): int
    {
        return match ($this->curve) {
            Curve::Secp256k1, Curve::NistP256, Curve::X25519 => 32,
            Curve::NistP384 => 48,
            Curve::NistP521 => 64
        };
    }

    /**
     * Thisi s called Nsk in the HPKE spec.
     */
    public function getSecretKeyLength(): int
    {
        return match ($this->curve) {
            Curve::Secp256k1, Curve::NistP256, Curve::X25519 => 32,
            Curve::NistP384 => 48,
            Curve::NistP521 => 66
        };
    }

    /**
     * This is called Nenc in the HPKE spec.
     *
     * @return int
     */
    public function getHeaderLength(): int
    {
        return $this->curve->encapsKeyLength();
    }

    public function getKemId(): string
    {
        // https://www.iana.org/assignments/hpke/hpke.xhtml
        return match ($this->curve) {
            Curve::X25519    => "\x00\x20",
            Curve::NistP256  => "\x00\x10",
            Curve::NistP384  => "\x00\x11",
            Curve::NistP521  => "\x00\x12",
            Curve::Secp256k1 => "\x00\x16"
        };
    }

    /**
     * This is different from the HPKE Suite ID
     *
     * @return string
     */
    public function getSuiteId(): string
    {
        return 'KEM' . $this->getKemId();
    }

    /**
     * Stubbed out so it can be overridden in unit tests
     *
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function generatePrivateKey(EasyECC $ecc): string|PrivateKeyInterface
    {
        if ($ecc->getCurveName() === 'sodium') {
            return sodium_crypto_box_keypair();
        }
        return $ecc->generatePrivateKey();
    }

    /**
     * Generate a keypair for Key Encapsulation.
     *
     * @return array{0: DecapsKeyInterface, 1: EncapsKeyInterface}
     *
     * @throws HPKEException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function generateKeys(): array
    {
        $ecc = $this->curve->getEasyECC();
        $keypair = $this->generatePrivateKey($ecc);

        // Special handling for libsodium
        if (is_string($keypair)) {
            return [
                new DecapsKey($this->curve, sodium_crypto_box_secretkey($keypair)),
                new EncapsKey($this->curve, sodium_crypto_box_publickey($keypair))
            ];
        }

        // Handle all other elliptic curves
        $sk = Util::gmpToBytes($keypair->getSecret(), $this->curve->decapsKeyLength());
        $ser = (new UncompressedPointSerializer());
        $pk = sodium_hex2bin($ser->serialize($keypair->getPublicKey()->getPoint()));
        return [
            new DecapsKey($this->curve, $sk),
            new EncapsKey($this->curve, $pk)
        ];
    }

    /**
     * @param EncapsKey $encapsKey
     * @return array{0: SymmetricKeyInterface, 1: string}
     *
     * @throws HPKEException
     * @throws InsecureCurveException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function encapsulate(EncapsKeyInterface $encapsKey): array
    {
        if (is_null($this->hpke)) {
            throw new HPKEException('HPKE not injected');
        }
        if (!hash_equals($encapsKey->curve->name, $this->curve->name)) {
            throw new TypeError('Encapsulation key must be meant for this curve');
        }
        [$ephSecret, $ephPublic] = $this->generateKeys();
        if (!$ephSecret instanceof DecapsKey || !$ephPublic instanceof EncapsKey) {
            throw new TypeError('Ephemeral key pair error');
        }
        $dh = $this->scalarMult($ephSecret, $encapsKey);
        $enc = $ephPublic->serializeForHeader();
        $kem_context = $enc . $encapsKey->serializeForHeader();
        $secret_length = $this->getSecretLength();
        $shared_secret = new SymmetricKey(
            $this->kdf->extractAndExpand(
                suiteId: $this->getSuiteId(),
                dh: $dh,
                kemContext: $kem_context,
                length: $secret_length
            )
        );
        return [$shared_secret, $enc];
    }

    /**
     * @param DecapsKey $decapsKey
     * @param string $enc
     * @return SymmetricKeyInterface
     *
     * @throws HPKEException
     * @throws InsecureCurveException
     * @throws SodiumException
     */
    public function decapsulate(
        DecapsKeyInterface $decapsKey,
        string $enc
    ): SymmetricKeyInterface {
        if (is_null($this->hpke)) {
            throw new HPKEException('HPKE not injected');
        }
        if (!hash_equals($decapsKey->curve->name, $this->curve->name)) {
            throw new TypeError('Encapsulation key must be meant for this curve');
        }
        $ephPublic = new EncapsKey($decapsKey->curve, $enc);
        $dh = $this->scalarMult($decapsKey, $ephPublic);
        $kem_context = $enc . $decapsKey->getEncapsKey()->bytes;
        $secret_length = $this->getSecretLength();
        return new SymmetricKey(
            $this->kdf->extractAndExpand($this->getSuiteId(), $dh, $kem_context, $secret_length)
        );
    }

    /**
     * @param EncapsKey $encapsKey
     * @param DecapsKey $decapsKey
     * @return array{0: SymmetricKeyInterface, 1: string}
     *
     * @throws HPKEException
     * @throws NotImplementedException
     * @throws SodiumException
     * @throws InsecureCurveException
     */
    public function authEncaps(EncapsKeyInterface $encapsKey, DecapsKeyInterface $decapsKey): array
    {
        if (is_null($this->hpke)) {
            throw new HPKEException('HPKE not injected');
        }
        if (!hash_equals($encapsKey->curve->name, $this->curve->name)) {
            throw new TypeError('Encapsulation key must be meant for this curve');
        }
        [$ephSecret, $ephPublic] = $this->generateKeys();
        if (!$ephSecret instanceof DecapsKey || !$ephPublic instanceof EncapsKey) {
            throw new TypeError('Ephemeral key pair error');
        }
        $dh = $this->scalarMult($ephSecret, $encapsKey) . $this->scalarMult($decapsKey, $encapsKey);
        $enc = $ephPublic->serializeForHeader();
        $kem_context = $enc .
            $encapsKey->serializeForHeader() .
            $decapsKey->getEncapsKey()->serializeForHeader();
        $secret_length = $this->curve->secretLength();
        $shared_secret = new SymmetricKey($this->kdf->extractAndExpand(
            $this->getSuiteId(), $dh, $kem_context, $secret_length
        ));
        return [$shared_secret, $enc];
    }

    /**
     * @param DecapsKey $decapsKey
     * @param EncapsKey $encapsKey
     * @param string $enc
     * @return SymmetricKeyInterface
     *
     * @throws HPKEException
     * @throws InsecureCurveException
     * @throws SodiumException
     */
    public function authDecaps(
        DecapsKeyInterface $decapsKey,
        EncapsKeyInterface $encapsKey,
        string $enc
    ): SymmetricKeyInterface {
        if (is_null($this->hpke)) {
            throw new HPKEException('HPKE not injected');
        }
        if (!hash_equals($decapsKey->curve->name, $this->curve->name)) {
            throw new TypeError('Encapsulation key must be meant for this curve');
        }
        $ephPublic = new EncapsKey($decapsKey->curve, $enc);
        $dh = $this->scalarMult($decapsKey, $ephPublic) . $this->scalarMult($decapsKey, $encapsKey);
        $kem_context = $enc .
            $encapsKey->serializeForHeader() .
            $decapsKey->getEncapsKey()->serializeForHeader();
        $secret_length = $this->curve->secretLength();
        return new SymmetricKey(
            $this->kdf->extractAndExpand($this->getSuiteId(), $dh, $kem_context, $secret_length)
        );
    }

    /**
     * Inject a reference to the HPKE class.
     *
     * @param HPKE $hpke
     * @return static
     */
    public function withHPKE(HPKE $hpke): static
    {
        $this->hpke = $hpke;
        return $this;
    }

    /**
     * @param DecapsKey $decapsKey
     * @param EncapsKey $encapsKey
     * @return string
     *
     * @throws HPKEException
     * @throws InsecureCurveException
     * @throws SodiumException
     */
    protected function scalarMult(DecapsKey $decapsKey, EncapsKey $encapsKey): string
    {
        return $this->curve->getEasyECC()->scalarmult(
            $decapsKey->toPrivateKey(),
            $encapsKey->toPublicKey()
        );
    }
}
