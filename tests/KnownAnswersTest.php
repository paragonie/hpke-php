<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests;

use ParagonIE\HPKE\Factory;
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\KEM\DHKEM\DecapsKey;
use ParagonIE\HPKE\KEM\DiffieHellmanKEM;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SodiumException;

#[CoversClass(HPKE::class)]
class KnownAnswersTest extends TestCase
{
    private const SUITE_MAP = [
        '32-1-1'  => 'DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM',
        '32-1-3'  => 'DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305',
        '16-1-1'  => 'DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM',
        '16-3-1'  => 'DHKEM(P-256, HKDF-SHA256), HKDF-SHA512, AES-128-GCM',
        '16-1-3'  => 'DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305',
        '18-3-2'  => 'DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM',
    ];

    public static function loadTestCases(int $mode): array
    {
        $jsonString = file_get_contents(__DIR__ . '/rfc-9180-test-vectors.json');
        if (!is_string($jsonString)) {
            throw new \Exception('Could not load rfc-9180-test-vectors.json');
        }
        $testCases = json_decode($jsonString, true);
        if (!is_array($testCases)) {
            throw new \Exception('Could not parse json string');
        }

        $filtered = [];
        foreach ($testCases as $tc) {
            if ($tc['mode'] !== $mode) {
                continue;
            }
            $key = sprintf('%d-%d-%d', $tc['kem_id'], $tc['kdf_id'], $tc['aead_id']);
            if (!array_key_exists($key, self::SUITE_MAP)) {
                continue;
            }
            $filtered []= [$tc];
        }
        return $filtered;
    }

    /**
     * @throws \Exception
     */
    public static function baseProvider(): array
    {
        return self::loadTestCases(0);
    }

    /**
     * @throws \Exception
     */
    public static function pskProvider(): array
    {
        return self::loadTestCases(1);
    }

    public function getSuiteFromVector(array $vector): HPKE
    {
        $key = sprintf('%d-%d-%d', $vector['kem_id'], $vector['kdf_id'], $vector['aead_id']);

        if (!array_key_exists($key, self::SUITE_MAP)) {
            $this->markTestSkipped(
                "Suite ({$key}) is not mapped — add it to SUITE_MAP to enable."
            );
        }

        return Factory::init(self::SUITE_MAP[$key]);
    }

    /**
     * @throws HPKEException
     * @throws SodiumException
     */
    #[DataProvider("baseProvider")]
    public function testHpkeBase(array $testGroup): void
    {
        $hpke = $this->getSuiteFromVector($testGroup);
        $dh = $hpke->kem;
        if (!($dh instanceof DiffieHellmanKEM)) {
            $this->markTestSkipped('Not a DH KEM');
        }
        $skRm = sodium_hex2bin($testGroup['skRm']);
        $info = sodium_hex2bin($testGroup['info']);
        $enc = sodium_hex2bin($testGroup['enc']);
        $receiver = $hpke->setupBaseReceiver(new DecapsKey($dh->curve, $skRm), $enc, $info);
        foreach ($testGroup['encryptions'] as $hexTests) {
            $ct = sodium_hex2bin($hexTests['ct']);
            $aad = sodium_hex2bin($hexTests['aad']);
            $opened = $receiver->open($ct, $aad);
            $this->assertSame($hexTests['pt'], sodium_bin2hex($opened), 'open');
        }
    }

    /**
     * @throws HPKEException
     * @throws SodiumException
     */
    #[DataProvider("pskProvider")]
    public function testHpkeBasePSK(array $testGroup): void
    {
        $hpke = $this->getSuiteFromVector($testGroup);
        $dh = $hpke->kem;
        if (!($dh instanceof DiffieHellmanKEM)) {
            $this->markTestSkipped('Not a DH KEM');
        }
        $skRm = sodium_hex2bin($testGroup['skRm']);
        $info = sodium_hex2bin($testGroup['info']);
        $enc = sodium_hex2bin($testGroup['enc']);
        $psk = sodium_hex2bin($testGroup['psk']);
        $pskID = sodium_hex2bin($testGroup['psk_id']);
        $receiver = $hpke->setupPSKReceiver(new DecapsKey($dh->curve, $skRm), $enc, $psk, $pskID, $info);
        foreach ($testGroup['encryptions'] as $hexTests) {
            $ct = sodium_hex2bin($hexTests['ct']);
            $aad = sodium_hex2bin($hexTests['aad']);
            $opened = $receiver->open($ct, $aad);
            $this->assertSame($hexTests['pt'], sodium_bin2hex($opened), 'open');
        }
    }
}
