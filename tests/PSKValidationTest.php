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

class PSKValidationTest extends TestCase
{
    /**
     * @throws HPKEException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testPskWithoutPskIdThrows(): void
    {
        $hpke = Factory::dhkem_x25519sha256_hkdf_sha256_aes128gcm();
        $kem = new DiffieHellmanKEM(
            Curve::X25519,
            $hpke->kdf
        );
        [$decaps, $encaps] = $kem->generateKeys();

        $this->expectException(HPKEException::class);
        $this->expectExceptionMessage('Inconsistent PSK Inputs');

        $hpke->setupPSKSender(
            $encaps,
            'my-preshared-key',
            ''  // empty pskID
        );
    }

    /**
     * @throws HPKEException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testPskIdWithoutPskThrows(): void
    {
        $hpke = Factory::dhkem_x25519sha256_hkdf_sha256_aes128gcm();
        $kem = new DiffieHellmanKEM(
            Curve::X25519,
            $hpke->kdf
        );
        [$decaps, $encaps] = $kem->generateKeys();

        $this->expectException(HPKEException::class);
        $this->expectExceptionMessage('Inconsistent PSK Inputs');

        $hpke->setupPSKSender(
            $encaps,
            '',           // empty PSK
            'my-psk-id'  // non-empty pskID
        );
    }

    /**
     * @throws HPKEException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testValidPskRoundTrip(): void
    {
        $hpke = Factory::dhkem_x25519sha256_hkdf_sha256_aes128gcm();
        $kem = new DiffieHellmanKEM(
            Curve::X25519,
            $hpke->kdf
        );
        [$decaps, $encaps] = $kem->generateKeys();

        $psk = 'my-preshared-key-value';
        $pskId = 'my-psk-identifier';
        $plaintext = 'Hello PSK mode!';
        $info = 'test-info';

        [$enc, $sender] = $hpke->setupPSKSender(
            $encaps,
            $psk,
            $pskId,
            $info
        );
        $ct = $sender->seal($plaintext, 'aad');

        $receiver = $hpke->setupPSKReceiver(
            $decaps,
            $enc,
            $psk,
            $pskId,
            $info
        );
        $decrypted = $receiver->open($ct, 'aad');

        $this->assertSame($plaintext, $decrypted);
    }

    /**
     * @throws HPKEException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testSingleBytePskRoundTrip(): void
    {
        $hpke = Factory::dhkem_x25519sha256_hkdf_sha256_aes128gcm();
        $kem = new DiffieHellmanKEM(
            Curve::X25519,
            $hpke->kdf
        );
        [$decaps, $encaps] = $kem->generateKeys();

        // Single-byte PSK and pskID: strlen=1, so (1-1)=0
        $psk = 'x';
        $pskId = 'y';
        $plaintext = 'boundary test';

        [$enc, $sender] = $hpke->setupPSKSender(
            $encaps,
            $psk,
            $pskId
        );
        $ct = $sender->seal($plaintext, '');

        $receiver = $hpke->setupPSKReceiver(
            $decaps,
            $enc,
            $psk,
            $pskId
        );
        $this->assertSame($plaintext, $receiver->open($ct, ''));
    }

    /**
     * @throws HPKEException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testSingleBytePskEmptyPskIdThrows(): void
    {
        $hpke = Factory::dhkem_x25519sha256_hkdf_sha256_aes128gcm();
        $kem = new DiffieHellmanKEM(
            Curve::X25519,
            $hpke->kdf
        );
        [$decaps, $encaps] = $kem->generateKeys();

        $this->expectException(HPKEException::class);
        $hpke->setupPSKSender($encaps, 'x', '');
    }

    /**
     * @throws HPKEException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testEmptyPskSingleBytePskIdThrows(): void
    {
        $hpke = Factory::dhkem_x25519sha256_hkdf_sha256_aes128gcm();
        $kem = new DiffieHellmanKEM(
            Curve::X25519,
            $hpke->kdf
        );
        [$decaps, $encaps] = $kem->generateKeys();

        $this->expectException(HPKEException::class);
        $hpke->setupPSKSender($encaps, '', 'y');
    }

    /**
     * @throws HPKEException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testWrongPskFailsDecrypt(): void
    {
        $hpke = Factory::dhkem_x25519sha256_hkdf_sha256_aes128gcm();
        $kem = new DiffieHellmanKEM(
            Curve::X25519,
            $hpke->kdf
        );
        [$decaps, $encaps] = $kem->generateKeys();

        $psk = 'correct-psk';
        $pskId = 'psk-id';

        [$enc, $sender] = $hpke->setupPSKSender(
            $encaps,
            $psk,
            $pskId
        );
        $ct = $sender->seal('secret', 'aad');

        $this->expectException(HPKEException::class);
        $receiver = $hpke->setupPSKReceiver(
            $decaps,
            $enc,
            'wrong-psk',
            $pskId
        );
        $receiver->open($ct, 'aad');
    }
}
