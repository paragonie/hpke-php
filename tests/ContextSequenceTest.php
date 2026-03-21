<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests;

use ParagonIE\EasyECC\Exception\NotImplementedException;
use ParagonIE\HPKE\Factory;
use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\KEM\DHKEM\Curve;
use ParagonIE\HPKE\KEM\DiffieHellmanKEM;
use PHPUnit\Framework\TestCase;
use SodiumException;

class ContextSequenceTest extends TestCase
{
    /**
     * @throws HPKEException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testMultipleSealsProduceUniqueCiphertexts(): void
    {
        $hpke = Factory::dhkem_x25519sha256_hkdf_sha256_aes128gcm();
        $kem = new DiffieHellmanKEM(Curve::X25519, $hpke->kdf);
        [$sk, $pk] = $kem->generateKeys();

        [$enc, $sender] = $hpke->setupBaseSender($pk);
        $receiver = $hpke->setupBaseReceiver($sk, $enc);

        $plaintext = 'same-message';
        $ciphertexts = [];

        for ($i = 0; $i < 5; $i++) {
            $ct = $sender->seal($plaintext, '');
            // Each ciphertext must be different due to nonce increment
            $this->assertNotContains(
                bin2hex($ct),
                $ciphertexts,
                "Ciphertext at seq=$i must be unique"
            );
            $ciphertexts[] = bin2hex($ct);

            // Receiver must successfully decrypt in order
            $pt = $receiver->open($ct, '');
            $this->assertSame($plaintext, $pt);
        }
    }

    /**
     * @throws HPKEException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testExportIsDeterministic(): void
    {
        $hpke = Factory::dhkem_x25519sha256_hkdf_sha256_aes128gcm();
        $kem = new DiffieHellmanKEM(Curve::X25519, $hpke->kdf);
        [$sk, $pk] = $kem->generateKeys();

        [$enc, $sender] = $hpke->setupBaseSender($pk);

        $a = $sender->export('context-a', 32);
        $b = $sender->export('context-a', 32);
        $c = $sender->export('context-b', 32);

        $this->assertSame(bin2hex($a), bin2hex($b));
        $this->assertNotSame(bin2hex($a), bin2hex($c));
        $this->assertSame(32, strlen($a));
    }
}
