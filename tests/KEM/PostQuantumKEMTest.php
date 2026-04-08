<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests\KEM;

use ParagonIE\HPKE\AEAD\{
    AES128GCM,
    AES256GCM,
    ChaCha20Poly1305
};
use ParagonIE\HPKE\{
    Hash,
    HPKE,
    HPKEException,
    Factory
};
use ParagonIE\HPKE\KDF\HKDF;
use ParagonIE\HPKE\KEM\PostQuantumKEM;
use ParagonIE\HPKE\KEM\PQKEM\{
    Algorithm,
    DecapsKey,
    EncapsKey
};
use PHPUnit\Framework\Attributes\{
    CoversClass,
    DataProvider
};
use ParagonIE\PQCrypto\Exception\{
    MLKemInternalException,
    PQCryptoCompatException
};
use PHPUnit\Framework\TestCase;
use SodiumException;

#[CoversClass(PostQuantumKEM::class)]
#[CoversClass(Algorithm::class)]
#[CoversClass(EncapsKey::class)]
#[CoversClass(DecapsKey::class)]
class PostQuantumKEMTest extends TestCase
{
    public static function pqkemProvider(): array
    {
        $sha256 = new HKDF(Hash::Sha256);
        $sha384 = new HKDF(Hash::Sha384);
        return [
            'ML-KEM-768, HKDF-SHA256, AES-128-GCM' => [
                new HPKE(
                    new PostQuantumKEM(Algorithm::MLKem768),
                    $sha256,
                    new AES128GCM(),
                ),
                "HPKE\x00\x41\x00\x01\x00\x01",
            ],
            'ML-KEM-768, HKDF-SHA256, ChaCha20Poly1305' => [
                new HPKE(
                    new PostQuantumKEM(Algorithm::MLKem768),
                    $sha256,
                    new ChaCha20Poly1305(),
                ),
                "HPKE\x00\x41\x00\x01\x00\x03",
            ],
            'ML-KEM-1024, HKDF-SHA384, AES-256-GCM' => [
                new HPKE(
                    new PostQuantumKEM(Algorithm::MLKem1024),
                    $sha384,
                    new AES256GCM(),
                ),
                "HPKE\x00\x42\x00\x02\x00\x02",
            ],
            'X-Wing, HKDF-SHA256, AES-128-GCM' => [
                new HPKE(
                    new PostQuantumKEM(Algorithm::XWing),
                    $sha256,
                    new AES128GCM(),
                ),
                "HPKE\x64\x7a\x00\x01\x00\x01",
            ],
            'X-Wing, HKDF-SHA256, ChaCha20Poly1305' => [
                new HPKE(
                    new PostQuantumKEM(Algorithm::XWing),
                    $sha256,
                    new ChaCha20Poly1305(),
                ),
                "HPKE\x64\x7a\x00\x01\x00\x03",
            ],
        ];
    }

    /**
     * @throws HPKEException
     */
    #[DataProvider('pqkemProvider')]
    public function testSealOpen(HPKE $hpke, string $suiteId): void
    {
        [$decapKey, $encapKey] = $hpke->kem->generateKeys();
        $message = 'post-quantum test plaintext';
        $aad = 'pq hpke aad';
        $ciphertext = $hpke->sealBase(
            $encapKey,
            $message,
            $aad,
            'phpunit'
        );
        $plaintext = $hpke->openBase(
            $decapKey,
            $ciphertext,
            $aad,
            'phpunit'
        );
        $this->assertSame(
            $plaintext,
            $message,
            'round-trip encryption/decryption'
        );
        $this->assertSame(
            bin2hex($suiteId),
            bin2hex($hpke->getSuiteId())
        );
    }

    /**
     * @throws HPKEException
     */
    #[DataProvider('pqkemProvider')]
    public function testSenderReceiver(HPKE $hpke, string $suiteId): void
    {
        [$dk, $ek] = $hpke->kem->generateKeys();
        [$enc, $sender] = $hpke->setupBaseSender($ek, 'test');
        $receiver = $hpke->setupBaseReceiver($dk, $enc, 'test');

        for ($i = 0; $i < 3; $i++) {
            $pt = "message $i";
            $aad = "aad-$i";
            $ct = $sender->seal($pt, $aad);
            $decrypted = $receiver->open($ct, $aad);
            $this->assertSame($pt, $decrypted);
        }
    }

    public function testKeyLengthValidation(): void
    {
        $this->expectException(HPKEException::class);
        new EncapsKey(Algorithm::MLKem768, str_repeat("\x00", 10));
    }

    public function testDecapsKeyLengthValidation(): void
    {
        $this->expectException(HPKEException::class);
        new DecapsKey(Algorithm::MLKem768, str_repeat("\x00", 10));
    }

    public function testAlgorithmMismatch(): void
    {
        $kem768 = new PostQuantumKEM(Algorithm::MLKem768);
        $kem1024 = new PostQuantumKEM(Algorithm::MLKem1024);

        [$dk, $ek] = $kem768->generateKeys();

        $this->expectException(HPKEException::class);
        $hpke = new HPKE($kem1024, new HKDF(Hash::Sha256), new AES128GCM());
        $kem1024->withHPKE($hpke)->encapsulate($ek);
    }

    public function testAlgorithmConstants(): void
    {
        // ML-KEM-768
        $this->assertSame(1184, Algorithm::MLKem768->encapsKeyLength());
        $this->assertSame(64, Algorithm::MLKem768->decapsKeyLength());
        $this->assertSame(1088, Algorithm::MLKem768->ciphertextLength());
        $this->assertSame(32, Algorithm::MLKem768->secretLength());
        $this->assertSame("\x00\x41", Algorithm::MLKem768->kemId());

        // ML-KEM-1024
        $this->assertSame(1568, Algorithm::MLKem1024->encapsKeyLength());
        $this->assertSame(64, Algorithm::MLKem1024->decapsKeyLength());
        $this->assertSame(1568, Algorithm::MLKem1024->ciphertextLength());
        $this->assertSame(32, Algorithm::MLKem1024->secretLength());
        $this->assertSame("\x00\x42", Algorithm::MLKem1024->kemId());

        // X-Wing
        $this->assertSame(1216, Algorithm::XWing->encapsKeyLength());
        $this->assertSame(32, Algorithm::XWing->decapsKeyLength());
        $this->assertSame(1120, Algorithm::XWing->ciphertextLength());
        $this->assertSame(32, Algorithm::XWing->secretLength());
        $this->assertSame("\x64\x7a", Algorithm::XWing->kemId());
    }

    /**
     * Test vectors from FiloSottile/hpke (draft-ietf-hpke-pq-03)
     */
    public static function hpkePqTestVectors(): array
    {
        $path = __DIR__ . '/../hpke-pq.json';
        if (!file_exists($path)) {
            return [];
        }
        $data = json_decode(file_get_contents($path), true);
        $vectors = [];

        foreach ($data as $v) {
            $kemId = $v['kem_id'];
            $kdfId = $v['kdf_id'];
            $aeadId = $v['aead_id'];
            $algo = self::kemIdToAlgorithm($kemId);
            if ($algo === null) {
                continue;
            }
            $kdf = self::kdfIdToHKDF($kdfId);
            $aead = self::aeadIdToAEAD($aeadId);
            if ($kdf === null || $aead === null) {
                continue;
            }
            $label = sprintf(
                '%s, %s, %s',
                $algo->value,
                $kdf->getSuiteName(),
                $aead->getSuiteName()
            );
            $vectors[$label] = [
                $algo,
                $kdf,
                $aead,
                $v,
            ];
        }
        return $vectors;
    }

    /**
     * @throws HPKEException
     * @throws MLKemInternalException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    #[DataProvider('hpkePqTestVectors')]
    public function testHpkePqVectors(
        Algorithm $algo,
        HKDF $kdf,
        mixed $aead,
        array $vector
    ): void {
        $kem = new PostQuantumKEM($algo);
        $hpke = new HPKE($kem, $kdf, $aead);

        $skRm = hex2bin($vector['skRm']);
        $enc = hex2bin($vector['enc']);
        $info = hex2bin($vector['info']);

        // Verify suite ID
        $expectedSuiteId = hex2bin($vector['suite_id']);
        $this->assertSame(
            bin2hex($expectedSuiteId),
            bin2hex($hpke->getSuiteId()),
            'suite_id mismatch'
        );

        // Test decapsulation
        $dk = new DecapsKey($algo, $skRm);
        $ss = $kem->withHPKE($hpke)->decapsulate($dk, $enc);
        $this->assertSame(
            $vector['shared_secret'],
            bin2hex($ss->bytes),
            'shared_secret mismatch'
        );

        // Test full HPKE receiver
        $receiver = $hpke->setupBaseReceiver($dk, $enc, $info);
        foreach ($vector['encryptions'] as $e) {
            $ct = hex2bin($e['ct']);
            $aadBytes = hex2bin($e['aad']);
            $expectedPt = hex2bin($e['pt']);
            $pt = $receiver->open($ct, $aadBytes);
            $this->assertSame(
                bin2hex($expectedPt),
                bin2hex($pt),
                'plaintext mismatch'
            );
        }
    }

    public function testFactoryInit(): void
    {
        $cases = [
            [
                'ML-KEM-768, HKDF-SHA256, AES-128-GCM',
                "HPKE\x00\x41\x00\x01\x00\x01",
            ],
            [
                'ML-KEM-1024, HKDF-SHA256, AES-256-GCM',
                "HPKE\x00\x42\x00\x01\x00\x02",
            ],
            [
                'X-Wing, HKDF-SHA256, ChaCha20Poly1305',
                "HPKE\x64\x7a\x00\x01\x00\x03",
            ],
        ];
        foreach ($cases as [$suiteName, $expectedSuiteId]) {
            $hpke = Factory::init($suiteName);
            $this->assertSame(
                bin2hex($expectedSuiteId),
                bin2hex($hpke->getSuiteId()),
                "Factory::init('$suiteName') suite ID"
            );
            $this->assertSame(
                $suiteName,
                $hpke->getSuiteName()
            );
        }
    }

    public function testFactoryMethods(): void
    {
        $hpke = Factory::mlkem768_hkdf_sha256_aes128gcm();
        $this->assertSame(
            'ML-KEM-768, HKDF-SHA256, AES-128-GCM',
            $hpke->getSuiteName()
        );

        $hpke = Factory::mlkem768_hkdf_sha256_chacha20poly1305();
        $this->assertSame(
            'ML-KEM-768, HKDF-SHA256, ChaCha20Poly1305',
            $hpke->getSuiteName()
        );

        $hpke = Factory::mlkem1024_hkdf_sha256_aes256gcm();
        $this->assertSame(
            'ML-KEM-1024, HKDF-SHA256, AES-256-GCM',
            $hpke->getSuiteName()
        );

        $hpke = Factory::xwing_hkdf_sha256_chacha20poly1305();
        $this->assertSame(
            'X-Wing, HKDF-SHA256, ChaCha20Poly1305',
            $hpke->getSuiteName()
        );
    }

    private static function kemIdToAlgorithm(int $id): ?Algorithm
    {
        return match ($id) {
            0x0041 => Algorithm::MLKem768,
            0x0042 => Algorithm::MLKem1024,
            0x647a => Algorithm::XWing,
            default => null,
        };
    }

    private static function kdfIdToHKDF(int $id): ?HKDF
    {
        return match ($id) {
            1 => new HKDF(Hash::Sha256),
            2 => new HKDF(Hash::Sha384),
            3 => new HKDF(Hash::Sha512),
            default => null,
        };
    }

    private static function aeadIdToAEAD(int $id): AES128GCM|AES256GCM|ChaCha20Poly1305|null
    {
        return match ($id) {
            1 => new AES128GCM(),
            2 => new AES256GCM(),
            3 => new ChaCha20Poly1305(),
            default => null,
        };
    }
}
