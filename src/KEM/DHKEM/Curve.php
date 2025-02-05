<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\KEM\DHKEM;

use Mdanter\Ecc\Curves\NistCurve;
use Mdanter\Ecc\Curves\SecgCurve;
use Mdanter\Ecc\Curves\SecureCurveFactory;
use Mdanter\Ecc\Exception\InsecureCurveException;
use Mdanter\Ecc\Primitives\CurveFpInterface;
use Mdanter\Ecc\Primitives\GeneratorPoint;
use ParagonIE\EasyECC\EasyECC;
use ParagonIE\HPKE\HPKEException;

enum Curve : string
{
    case X25519 = 'X25519';
    case Secp256k1 = 'Secp256k1';
    case NistP256 = 'P-256';
    case NistP384 = 'P-384';
    case NistP521 = 'P-521';

    public function decapsKeyLength(): int
    {
        return match($this) {
            self::X25519, self::Secp256k1, self::NistP256 => 32,
            self::NistP384 => 48,
            self::NistP521 => 66,
        };
    }

    public function encapsKeyLength(): int
    {
        return match($this) {
            self::X25519  => 32,
            self::Secp256k1, self::NistP256 => 65,
            self::NistP384 => 97,
            self::NistP521 => 133,
        };
    }

    public function getEasyECC(): EasyECC
    {
        return match($this) {
            self::X25519    => new EasyECC(),
            self::NistP256  => new EasyECC('P256'),
            self::NistP384  => new EasyECC('P384'),
            self::NistP521  => new EasyECC('P521'),
            self::Secp256k1 => new EasyECC('K256')
        };
    }

    /**
     * @throws InsecureCurveException
     * @throws HPKEException
     */
    public function getCurveFp(): CurveFpInterface
    {
        return match($this) {
            self::X25519 =>
                throw new HPKEException('X25519 does not have a phpecc class to call; use libsodium'),
            self::Secp256k1 => SecureCurveFactory::getCurveByName(SecgCurve::NAME_SECP_256K1),
            self::NistP256 => SecureCurveFactory::getCurveByName(NistCurve::NAME_P256),
            self::NistP384 => SecureCurveFactory::getCurveByName(NistCurve::NAME_P384),
            self::NistP521 => SecureCurveFactory::getCurveByName(NistCurve::NAME_P521),
        };
    }
    /**
     * @throws InsecureCurveException
     * @throws HPKEException
     */
    public function getGenerator(): GeneratorPoint
    {
        return match($this) {
            self::X25519 =>
                throw new HPKEException('X25519 does not have a phpecc class to call; use libsodium'),
            self::Secp256k1 =>
                SecureCurveFactory::getGeneratorByName(SecgCurve::NAME_SECP_256K1),
            self::NistP256  =>
                SecureCurveFactory::getGeneratorByName(NistCurve::NAME_P256),
            self::NistP384  =>
                SecureCurveFactory::getGeneratorByName(NistCurve::NAME_P384),
            self::NistP521  =>
                SecureCurveFactory::getGeneratorByName(NistCurve::NAME_P521),
        };
    }
}
