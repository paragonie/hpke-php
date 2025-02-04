<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests\KDF;

use ParagonIE\HPKE\AEAD\{
    AES128GCM,
    AES256GCM,
    ChaCha20Poly1305
};
use ParagonIE\HPKE\Hash;
use ParagonIE\HPKE\KDF\HKDF;
use ParagonIE\HPKE\KEM\{
    DHKEM\Curve,
    DiffieHellmanKEM
};
use PHPUnit\Framework\Attributes\{
    CoversClass,
    DataProvider
};
use PHPUnit\Framework\TestCase;
use SodiumException;

#[CoversClass(HKDF::class)]
class HKDFTest extends TestCase
{
    /**
     * Omits the SHA-1 test vectors
     */
    public static function rfc5869TestVectors(): array
    {
        $sha256 = new HKDF(Hash::Sha256);
        return [
            'Test Case 1' => [
                $sha256,
                '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5',
                '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
                '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
                'f0f1f2f3f4f5f6f7f8f9',
                42,
                '000102030405060708090a0b0c',
            ],
            'Test Case 2' => [
                $sha256,
                '06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244',
                'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87',
                '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f',
                'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
                82,
                '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf'
            ],
            'Test Case 3' => [
                $sha256,
                '19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04',
                '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
                '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
                '',
                42,
                null
            ]
        ];
    }

    public static function rfc9180(): array
    {
        $sha256 = new HKDF(Hash::Sha256);
        $sha512 = new HKDF(Hash::Sha512);

        // KEMs
        $kem_x25519_id = (new DiffieHellmanKEM(Curve::X25519, $sha256))->getKemId();
        $kem_p256_id = (new DiffieHellmanKEM(Curve::NistP256, $sha256))->getKemId();
        $kem_p521_id = (new DiffieHellmanKEM(Curve::NistP521, $sha512))->getKemId();

        // KDFs
        $kdf_sha256_id = $sha256->getKdfId();
        $kdf_sha512_id = $sha512->getKdfId();

        // AEADs
        $aes128 = (new AES128GCM());
        $aes256 = (new AES256GCM());
        $chapoly = (new ChaCha20Poly1305());

        // Return the test cases:
        return [
            'DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM' => [
                $sha256,
                "HPKE" . $kem_x25519_id . $kdf_sha256_id . $aes128->getAeadId(),
                [
                    'nk' =>
                        $aes128->keyLength(),
                    'mode' =>
                        '00',
                    'info' =>
                        '4f6465206f6e2061204772656369616e2055726e',
                    'shared_secret' =>
                        'fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc',
                    'key_schedule_context' =>
                        '00725611c9d98c07c03f60095cd32d400d8347d45ed67097bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449',
                    'secret' =>
                        '12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397',
                    'key' =>
                        '4531685d41d65f03dc48f6b8302c05b0',
                    'base_nonce' =>
                        '56d890e5accaaf011cff4b7d',
                    'exporter_secret' =>
                        '45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8',
                ]
            ],
            'DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305' => [
                $sha256,
                "HPKE" . $kem_x25519_id . $kdf_sha256_id . $chapoly->getAeadId(),
                [
                    'nk' =>
                        $chapoly->keyLength(),
                    'mode' =>
                        '00',
                    'info' =>
                        '4f6465206f6e2061204772656369616e2055726e',
                    'shared_secret' =>
                        '0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7',
                    'key_schedule_context' =>
                        '00431df6cd95e11ff49d7013563baf7f11588c75a6611ee2a4404a49306ae4cfc5b69c5718a60cc5876c358d3f7fc31ddb598503f67be58ea1e798c0bb19eb9796',
                    'secret' =>
                        '5b9cd775e64b437a2335cf499361b2e0d5e444d5cb41a8a53336d8fe402282c6',
                    'key' =>
                        'ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91',
                    'base_nonce' =>
                        '5c4d98150661b848853b547f',
                    'exporter_secret' =>
                        'a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922',
                ]
            ],
            'DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM' => [
                $sha256,
                "HPKE" . $kem_p256_id . $kdf_sha256_id . $aes128->getAeadId(),
                [
                    'nk' =>
                        $aes128->keyLength(),
                    'mode' =>
                        '00',
                    'info' =>
                        '4f6465206f6e2061204772656369616e2055726e',
                    'shared_secret' =>
                        'c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8',
                    'key_schedule_context' =>
                        '00b88d4e6d91759e65e87c470e8b9141113e9ad5f0c8ceefc1e088c82e6980500798e486f9c9c09c9b5c753ac72d6005de254c607d1b534ed11d493ae1c1d9ac85',
                    'secret' =>
                        '2eb7b6bf138f6b5aff857414a058a3f1750054a9ba1f72c2cf0684a6f20b10e1',
                    'key' =>
                        '868c066ef58aae6dc589b6cfdd18f97e',
                    'base_nonce' =>
                        '4e0bc5018beba4bf004cca59',
                    'exporter_secret' =>
                        '14ad94af484a7ad3ef40e9f3be99ecc6fa9036df9d4920548424df127ee0d99f',
                ]
            ],
            'DHKEM(P-256, HKDF-SHA256), HKDF-SHA512, AES-128-GCM' => [
                $sha512,
                "HPKE" . $kem_p256_id . $kdf_sha512_id . $aes128->getAeadId(),
                [
                    'nk' =>
                        $aes128->keyLength(),
                    'mode' =>
                        '00',
                    'info' =>
                        '4f6465206f6e2061204772656369616e2055726e',
                    'shared_secret' =>
                        '02f584736390fc93f5b4ad039826a3fa08e9911bd1215a3db8e8791ba533cafd',
                    'key_schedule_context' =>
                        '005b8a3617af7789ee716e7911c7e77f84cdc4cc46e60fb7e19e4059f9aeadc00585e26874d1ddde76e551a7679cd47168c466f6e1f705cc9374c192778a34fcd5ca221d77e229a9d11b654de7942d685069c633b2362ce3b3d8ea4891c9a2a87a4eb7cdb289ba5e2ecbf8cd2c8498bb4a383dc021454d70d46fcbbad1252ef4f9',
                    'secret' =>
                        '0c7acdab61693f936c4c1256c78e7be30eebfe466812f9cc49f0b58dc970328dfc03ea359be0250a471b1635a193d2dfa8cb23c90aa2e25025b892a725353eeb',
                    'key' =>
                        '090ca96e5f8aa02b69fac360da50ddf9',
                    'base_nonce' =>
                        '9c995e621bf9a20c5ca45546',
                    'exporter_secret' =>
                        '4a7abb2ac43e6553f129b2c5750a7e82d149a76ed56dc342d7bca61e26d494f4855dff0d0165f27ce57756f7f16baca006539bb8e4518987ba610480ac03efa8',
                ]
            ],
            'DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305' => [
                $sha256,
                "HPKE" . $kem_p256_id . $kdf_sha256_id . $chapoly->getAeadId(),
                [
                    'nk' =>
                        $chapoly->keyLength(),
                    'mode' =>
                        '00',
                    'info' =>
                        '4f6465206f6e2061204772656369616e2055726e',
                    'shared_secret' =>
                        '806520f82ef0b03c823b7fc524b6b55a088f566b9751b89551c170f4113bd850',
                    'key_schedule_context' =>
                        '00b738cd703db7b4106e93b4621e9a19c89c838e55964240e5d3f331aaf8b0d58b2e986ea1c671b61cf45eec134dac0bae58ec6f63e790b1400b47c33038b0269c',
                    'secret' =>
                        'fe891101629aa355aad68eff3cc5170d057eca0c7573f6575e91f9783e1d4506',
                    'key' =>
                        'a8f45490a92a3b04d1dbf6cf2c3939ad8bfc9bfcb97c04bffe116730c9dfe3fc',
                    'base_nonce' =>
                        '726b4390ed2209809f58c693',
                    'exporter_secret' =>
                        '4f9bd9b3a8db7d7c3a5b9d44fdc1f6e37d5d77689ade5ec44a7242016e6aa205',
                ]
            ],
            'DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM' => [
                $sha512,
                "HPKE" . $kem_p521_id . $kdf_sha512_id . $aes256->getAeadId(),
                [
                    'nk' =>
                        $aes256->keyLength(),
                    'mode' =>
                        '00',
                    'info' =>
                        '4f6465206f6e2061204772656369616e2055726e',
                    'shared_secret' =>
                        '776ab421302f6eff7d7cb5cb1adaea0cd50872c71c2d63c30c4f1d5e43653336fef33b103c67e7a98add2d3b66e2fda95b5b2a667aa9dac7e59cc1d46d30e818',
                    'key_schedule_context' =>
                        '0083a27c5b2358ab4dae1b2f5d8f57f10ccccc822a473326f543f239a70aee46347324e84e02d7651a10d08fb3dda739d22d50c53fbfa8122baacd0f9ae5913072ef45baa1f3a4b169e141feb957e48d03f28c837d8904c3d6775308c3d3faa75dd64adfa44e1a1141edf9349959b8f8e5291cbdc56f62b0ed6527d692e85b09a4',
                    'secret' =>
                        '49fd9f53b0f93732555b2054edfdc0e3101000d75df714b98ce5aa295a37f1b18dfa86a1c37286d805d3ea09a20b72f93c21e83955a1f01eb7c5eead563d21e7',
                    'key' =>
                        '751e346ce8f0ddb2305c8a2a85c70d5cf559c53093656be636b9406d4d7d1b70',
                    'base_nonce' =>
                        '55ff7a7d739c69f44b25447b',
                    'exporter_secret' =>
                        'e4ff9dfbc732a2b9c75823763c5ccc954a2c0648fc6de80a58581252d0ee3215388a4455e69086b50b87eb28c169a52f42e71de4ca61c920e7bd24c95cc3f992',
                ]
            ],
        ];
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider('rfc5869TestVectors')]
    public function testRfc5869(
        HKDF $kdf,
        string $prk_hex,
        string $okm_hex,
        string $ikm_hex,
        string $info_hex,
        int $length,
        ?string $salt_hex = null
    ): void {
        $ikm = sodium_hex2bin($ikm_hex);
        $info = sodium_hex2bin($info_hex);
        $salt = is_null($salt_hex) ? '' : sodium_hex2bin($salt_hex);

        // Test the combined mode
        $output = $kdf->deriveBytes($ikm, $info, $salt, $length);
        $this->assertSame($okm_hex, sodium_bin2hex($output));

        // Now let's test extract/expand separately
        $prk = $kdf->extract($ikm, $salt);
        $this->assertSame($prk_hex, sodium_bin2hex($prk), 'HKDF-extract');
        $result = $kdf->expand($prk, $info, $length);
        $this->assertSame($okm_hex, sodium_bin2hex($result), 'HKDF-expand');
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider('rfc9180')]
    public function testRfc9180(
        HKDF $kdf,
        string $suiteId,
        array $testVectorsInHex = []
    ): void {
        // We aren't testing it at this level.
        $info = sodium_hex2bin($testVectorsInHex['info']);
        $mode = sodium_hex2bin($testVectorsInHex['mode']);
        $info_hash = $kdf->labeledExtract(
            suiteId: $suiteId,
            ikm: $info,
            label: 'info_hash'
        );
        $psk_id_hash = $kdf->labeledExtract(
            suiteId: $suiteId,
            ikm: '',
            label: 'psk_id_hash'
        );
        $this->assertSame(
            $testVectorsInHex['key_schedule_context'],
            sodium_bin2hex($mode . $psk_id_hash . $info_hash),
            'info hashing'
        );

        $shared_secret = sodium_hex2bin($testVectorsInHex['shared_secret']);
        $actual_secret = $kdf->labeledExtract(
            suiteId: $suiteId,
            ikm: '',
            label: 'secret',
            salt: $shared_secret
        );
        $this->assertSame(
            $testVectorsInHex['secret'],
            sodium_bin2hex($actual_secret),
            'secret'
        );

        $nk = $testVectorsInHex['nk'];
        $secret = sodium_hex2bin($testVectorsInHex['secret']);
        $key_schedule_context = sodium_hex2bin($testVectorsInHex['key_schedule_context']);
        $actual_key = $kdf->labeledExpand(
            suiteId: $suiteId,
            prk: $secret,
            label: 'key',
            info: $key_schedule_context,
            length: $nk
        );
        $this->assertSame(
            $testVectorsInHex['key'],
            sodium_bin2hex($actual_key),
            'key'
        );

        $actual_base_nonce = $kdf->labeledExpand(
            suiteId: $suiteId,
            prk: $secret,
            label: 'base_nonce',
            info: $key_schedule_context,
            length: 12 // This is pretty universal for all AEADs in scope
        );
        $this->assertSame(
            $testVectorsInHex['base_nonce'],
            sodium_bin2hex($actual_base_nonce),
            'base_nonce'
        );

        $actual_exp = $kdf->labeledExpand(
            suiteId: $suiteId,
            prk: $secret,
            label: 'exp',
            info: $key_schedule_context,
            length: $kdf->getHashLength()
        );
        $this->assertSame(
            $testVectorsInHex['exporter_secret'],
            sodium_bin2hex($actual_exp),
            'exporter_secret'
        );
    }
}
