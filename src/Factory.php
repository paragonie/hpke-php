<?php
declare(strict_types=1);
namespace ParagonIE\HPKE;

use ParagonIE\HPKE\AEAD\{
    AES128GCM,
    AES256GCM,
    ChaCha20Poly1305,
    ExportOnly
};
use ParagonIE\HPKE\Interfaces\KDFInterface;
use ParagonIE\HPKE\KDF\HKDF;
use ParagonIE\HPKE\KEM\DHKEM\Curve;
use ParagonIE\HPKE\KEM\DiffieHellmanKEM;

abstract class Factory
{
    const PATTERN = '#^(.+?)' .
        '\(' .
            '([A-Za-z0-9\-]+?),' . '?\s*' . '([A-Za-z0-9\-]+?)' .
        '\)' .
        ',?' . '\s*?' . '([A-Za-z0-9\-]+?)' . ',?\s*?' . '([A-Za-z0-9\-\s]+?)' .
    '$#';

    /**
     * @throws HPKEException
     */
    public static function init(string $parameterString): HPKE
    {
        $matches = [];
        $matched = preg_match(
            self::PATTERN,
            $parameterString,
            $matches
        );
        if (!$matched) {
            throw new HPKEException('Invalid KEM name');
        }
        $curve = Curve::from($matches[2]);
        $innerKdf = self::getKDF($matches[3]);
        $kem = match ($matches[1]) {
            'DHKEM' => new DiffieHellmanKEM($curve, $innerKdf),
            default => throw new HPKEException('Unknown KEM')
        };

        $outerKdf = self::getKDF($matches[4]);
        $aead = match (trim($matches[5])) {
            'AES-128-GCM' =>
                new AES128GCM(),
            'AES-256-GCM' =>
                new AES256GCM(),
            'ChaCha20Poly1305', 'ChaCha20-Poly1305' =>
                new ChaCha20Poly1305(),
            'Export-Only AEAD' =>
                new ExportOnly(),
            default =>
                throw new HPKEException('Unknown AEAD mode')
        };
        return new HPKE($kem, $outerKdf, $aead);
    }

    /**
     * @throws HPKEException
     */
    protected static function getKDF(string $kdfName): KDFInterface
    {
        return match ($kdfName) {
            'HKDF-SHA256' => new HKDF(Hash::Sha256),
            'HKDF-SHA384' => new HKDF(Hash::Sha384),
            'HKDF-SHA512' => new HKDF(Hash::Sha512),
            default => throw new HPKEException('Unknown KDF: ' . $kdfName)
        };
    }

    public static function dhkem_x25519sha256_hkdf_sha256_aes128gcm(): HPKE
    {
        return new HPKE(
            new DiffieHellmanKEM(Curve::X25519, new HKDF(Hash::Sha256)),
            new HKDF(Hash::Sha256),
            new AES128GCM(),
        );
    }

    public static function dhkem_x25519sha256_hkdf_sha256_chacha20poly1305(): HPKE
    {
        return new HPKE(
            new DiffieHellmanKEM(Curve::X25519, new HKDF(Hash::Sha256)),
            new HKDF(Hash::Sha256),
            new ChaCha20Poly1305(),
        );
    }

    public static function dhkem_p256sha256_hkdf_sha256_aes128gcm(): HPKE
    {
        return new HPKE(
            new DiffieHellmanKEM(Curve::NistP256, new HKDF(Hash::Sha256)),
            new HKDF(Hash::Sha256),
            new AES128GCM(),
        );
    }

    public static function dhkem_p256sha256_hkdf_sha512_aes128gcm(): HPKE
    {
        return new HPKE(
            new DiffieHellmanKEM(Curve::NistP256, new HKDF(Hash::Sha256)),
            new HKDF(Hash::Sha512),
            new AES128GCM(),
        );
    }
    public static function dhkem_p256sha256_hkdf_sha256_chacha20poly1305(): HPKE
    {
        return new HPKE(
            new DiffieHellmanKEM(Curve::NistP256, new HKDF(Hash::Sha256)),
            new HKDF(Hash::Sha256),
            new ChaCha20Poly1305(),
        );
    }

    public static function dhkem_p521sha512_hkdf_sha512_aes256gcm(): HPKE
    {
        return new HPKE(
            new DiffieHellmanKEM(Curve::NistP521, new HKDF(Hash::Sha512)),
            new HKDF(Hash::Sha512),
            new AES256GCM(),
        );
    }
    public static function dhkem_x25519sha256_hkdf_sha256_exportonly(): HPKE
    {
        return new HPKE(
            new DiffieHellmanKEM(Curve::X25519, new HKDF(Hash::Sha256)),
            new HKDF(Hash::Sha256),
            new ExportOnly(),
        );
    }
}
