<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests\KEM;

use Mdanter\Ecc\Crypto\Key\PrivateKey;
use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Math\GmpMath;
use ParagonIE\EasyECC\EasyECC;
use ParagonIE\HPKE\KEM\DHKEM\Curve;
use ParagonIE\HPKE\KEM\DiffieHellmanKEM;
use ParagonIE\HPKE\Util;

class MockDHKEM extends DiffieHellmanKEM
{
    private string|PrivateKeyInterface|null $mockPrivateKey = null;

    public function setPrivateKey(string|PrivateKeyInterface $mockPrivateKey = null): static
    {
        if ($this->curve === Curve::X25519) {
            if (strlen($mockPrivateKey) === 32) {
                $pk = sodium_crypto_box_publickey_from_secretkey($mockPrivateKey);
                $this->mockPrivateKey = $mockPrivateKey . $pk;
                return $this;
            }
        }
        $this->mockPrivateKey = $mockPrivateKey;
        return $this;
    }

    public function generatePrivateKey(EasyECC $ecc): string|PrivateKeyInterface
    {
        if (is_null($this->mockPrivateKey)) {
            return parent::generatePrivateKey($ecc);
        }
        if ($ecc->getCurveName() === 'sodium') {
            $result = $this->mockPrivateKey;
        } else {
            $gen = EasyECC::getGenerator($ecc->getCurveName());
            $result = new PrivateKey(
                new GmpMath(),
                $gen,
                Util::bytesToGmp($this->mockPrivateKey)
            );
        }
        unset($this->mockPrivateKey);
        return $result;
    }
}
