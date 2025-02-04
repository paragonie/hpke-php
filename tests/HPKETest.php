<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests;

use ParagonIE\HPKE\AEAD\{AES128GCM, AES256GCM, ChaCha20Poly1305, ExportOnly};
use ParagonIE\HPKE\{Hash, HPKE, HPKEException, Interfaces\AEADInterface, Interfaces\KDFInterface, Tests\KEM\MockDHKEM};
use ParagonIE\HPKE\KDF\HKDF;
use ParagonIE\HPKE\KEM\{DHKEM\Curve, DHKEM\DecapsKey, DHKEM\EncapsKey, DiffieHellmanKEM};
use PHPUnit\Framework\Attributes\{
    CoversClass,
    DataProvider
};
use PHPUnit\Framework\TestCase;
use SodiumException;

#[CoversClass(HPKE::class)]
class HPKETest extends TestCase
{
    public static function hpkeProvider(): array
    {
        $sha256 = new HKDF(Hash::Sha256);
        $sha384 = new HKDF(Hash::Sha384);
        $sha512 = new HKDF(Hash::Sha512);
        return [
            'DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM' => [
                new HPKE(
                    new DiffieHellmanKEM(Curve::X25519, $sha256),
                    $sha256,
                    new AES128GCM(),
                ),
                "HPKE\x00\x20\x00\x01\x00\x01",
                [$sha256, $sha256],
            ],
            'DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305' => [
                new HPKE(
                    new DiffieHellmanKEM(Curve::X25519, $sha256),
                    $sha256,
                    new ChaCha20Poly1305(),
                ),
                "HPKE\x00\x20\x00\x01\x00\x03",
                [$sha256, $sha256],
            ],
            'DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM' => [
                new HPKE(
                    new DiffieHellmanKEM(Curve::NistP256, $sha256),
                    $sha256,
                    new AES128GCM()
                ),
                "HPKE\x00\x10\x00\x01\x00\x01",
                [$sha256, $sha256],
            ],
            'DHKEM(P-256, HKDF-SHA256), HKDF-SHA512, AES-128-GCM' => [
                new HPKE(
                    new DiffieHellmanKEM(Curve::NistP256, $sha256),
                    $sha512,
                    new AES128GCM()
                ),
                "HPKE\x00\x10\x00\x03\x00\x01",
                [$sha256, $sha512],
            ],
            'DHKEM(P-384, HKDF-SHA384), HKDF-SHA384, AES-256-GCM' => [
                new HPKE(
                    new DiffieHellmanKEM(Curve::NistP384, $sha384),
                    $sha384,
                    new AES256GCM()
                ),
                "HPKE\x00\x11\x00\x02\x00\x02",
                [$sha384, $sha384],
            ]
        ];
    }

    /**
     * @throws HPKEException
     */
    #[DataProvider('hpkeProvider')]
    public function testSealOpen(HPKE $hpke, string $suiteId, array $kdfs): void
    {
        [$decapKey, $encapKey] = $hpke->kem->generateKeys();
        $message = 'this is a testing plaintext';
        $aad = 'unit testing with phpunit';
        $ciphertext = $hpke->sealBase($encapKey, $message, $aad, 'phpunit');
        $plaintext = $hpke->openBase($decapKey, $ciphertext, $aad, 'phpunit');
        $this->assertSame($plaintext, $message, 'idempotent encryption/decryption');
        $this->assertSame(bin2hex($suiteId), bin2hex($hpke->getSuiteId()));
        $this->assertSame($kdfs[0]->hash->name, $hpke->kem->kdf->hash->name);
        $this->assertSame($kdfs[1]->hash->name, $hpke->kdf->hash->name);
    }

    public static function rfc9180TestVectors(): array
    {
        $kdf_sha256 = new HKDF(Hash::Sha256);
        $kdf_sha512 = new HKDF(Hash::Sha512);

        $dhkem_x25519 = new MockDHKEM(Curve::X25519, $kdf_sha256);
        $dhkem_p256 = new MockDHKEM(Curve::NistP256, $kdf_sha256);
        $dhkem_p521 = new MockDHKEM(Curve::NistP521, $kdf_sha512);

        $aes128 = new AES128GCM();
        $aes256 = new AES256GCM();
        $chapoly = new ChaCha20Poly1305();
        $export = new ExportOnly();

        return [
            'DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM' => [
                new HPKE($dhkem_x25519, $kdf_sha256, $aes128),
                [
                    'info' => '4f6465206f6e2061204772656369616e2055726e',
                    'skEm' => '52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736',
                    'pkRm' => '3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d',
                    'skRm' => '4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8',
                    'enc'  => '37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431'
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => 'f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a'
                    ],
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d31',
                        'ct' => 'af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84'
                    ],
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d32',
                        'ct' => '498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180'
                    ]
                ]
            ],
            'DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305' => [
                new HPKE($dhkem_x25519, $kdf_sha256, $chapoly),
                [
                    'info' => '4f6465206f6e2061204772656369616e2055726e',
                    'skEm' => 'f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600',
                    'pkRm' => '4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a',
                    'skRm' => '8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb',
                    'enc'  => '1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a'
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => '1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28'
                    ],
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d31',
                        'ct' => '6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c'
                    ],
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d32',
                        'ct' => '71146bd6795ccc9c49ce25dda112a48f202ad220559502cef1f34271e0cb4b02b4f10ecac6f48c32f878fae86b'
                    ]
                ]
            ],
            'DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM' => [
                new HPKE($dhkem_p256, $kdf_sha256, $aes128),
                [
                    'info' => '4f6465206f6e2061204772656369616e2055726e',
                    'skEm' => '4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb',
                    'pkRm' => '04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0',
                    'skRm' => 'f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2',
                    'enc'  => '04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4'
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => '5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434'
                    ],
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d31',
                        'ct' => 'fa6f037b47fc21826b610172ca9637e82d6e5801eb31cbd3748271affd4ecb06646e0329cbdf3c3cd655b28e82'
                    ],
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d32',
                        'ct' => '895cabfac50ce6c6eb02ffe6c048bf53b7f7be9a91fc559402cbc5b8dcaeb52b2ccc93e466c28fb55fed7a7fec'
                    ]
                ]
            ],
            'DHKEM(P-256, HKDF-SHA256), HKDF-SHA512, AES-128-GCM' => [
                new HPKE($dhkem_p256, $kdf_sha512, $aes128),
                [
                    'info' => '4f6465206f6e2061204772656369616e2055726e',
                    'skEm' => '2292bf14bb6e15b8c81a0f45b7a6e93e32d830e48cca702e0affcfb4d07e1b5c',
                    'pkRm' => '04085aa5b665dc3826f9650ccbcc471be268c8ada866422f739e2d531d4a8818a9466bc6b449357096232919ec4fe9070ccbac4aac30f4a1a53efcf7af90610edd',
                    'skRm' => '3ac8530ad1b01885960fab38cf3cdc4f7aef121eaa239f222623614b4079fb38',
                    'enc'  => '0493ed86735bdfb978cc055c98b45695ad7ce61ce748f4dd63c525a3b8d53a15565c6897888070070c1579db1f86aaa56deb8297e64db7e8924e72866f9a472580'
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => 'd3cf4984931484a080f74c1bb2a6782700dc1fef9abe8442e44a6f09044c88907200b332003543754eb51917ba'
                    ],
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d31',
                        'ct' => 'd14414555a47269dfead9fbf26abb303365e40709a4ed16eaefe1f2070f1ddeb1bdd94d9e41186f124e0acc62d'
                    ],
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d32',
                        'ct' => '9bba136cade5c4069707ba91a61932e2cbedda2d9c7bdc33515aa01dd0e0f7e9d3579bf4016dec37da4aafa800'
                    ]
                ]
            ],
            'DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305' => [
                new HPKE($dhkem_p256, $kdf_sha256, $chapoly),
                [
                    'info' => '4f6465206f6e2061204772656369616e2055726e',
                    'skEm' => '7550253e1147aae48839c1f8af80d2770fb7a4c763afe7d0afa7e0f42a5b3689',
                    'pkRm' => '04a697bffde9405c992883c5c439d6cc358170b51af72812333b015621dc0f40bad9bb726f68a5c013806a790ec716ab8669f84f6b694596c2987cf35baba2a006',
                    'skRm' => 'a4d1c55836aa30f9b3fbb6ac98d338c877c2867dd3a77396d13f68d3ab150d3b',
                    'enc'  => '04c07836a0206e04e31d8ae99bfd549380b072a1b1b82e563c935c095827824fc1559eac6fb9e3c70cd3193968994e7fe9781aa103f5b50e934b5b2f387e381291'
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => '6469c41c5c81d3aa85432531ecf6460ec945bde1eb428cb2fedf7a29f5a685b4ccb0d057f03ea2952a27bb458b'
                    ],
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d31',
                        'ct' => 'f1564199f7e0e110ec9c1bcdde332177fc35c1adf6e57f8d1df24022227ffa8716862dbda2b1dc546c9d114374'
                    ],
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d32',
                        'ct' => '39de89728bcb774269f882af8dc5369e4f3d6322d986e872b3a8d074c7c18e8549ff3f85b6d6592ff87c3f310c'
                    ]
                ]
            ],
            'DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM' => [
                new HPKE($dhkem_p521, $kdf_sha512, $aes256),
                [
                    'info' => '4f6465206f6e2061204772656369616e2055726e',
                    'skEm' => '014784c692da35df6ecde98ee43ac425dbdd0969c0c72b42f2e708ab9d535415a8569bdacfcc0a114c85b8e3f26acf4d68115f8c91a66178cdbd03b7bcc5291e374b',
                    'pkRm' => '0401b45498c1714e2dce167d3caf162e45e0642afc7ed435df7902ccae0e84ba0f7d373f646b7738bbbdca11ed91bdeae3cdcba3301f2457be452f271fa6837580e661012af49583a62e48d44bed350c7118c0d8dc861c238c72a2bda17f64704f464b57338e7f40b60959480c0e58e6559b190d81663ed816e523b6b6a418f66d2451ec64',
                    'skRm' => '01462680369ae375e4b3791070a7458ed527842f6a98a79ff5e0d4cbde83c27196a3916956655523a6a2556a7af62c5cadabe2ef9da3760bb21e005202f7b2462847',
                    'enc'  => '040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8900aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed0692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0'
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => '170f8beddfe949b75ef9c387e201baf4132fa7374593dfafa90768788b7b2b200aafcc6d80ea4c795a7c5b841a'
                    ],
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d31',
                        'ct' => 'd9ee248e220ca24ac00bbbe7e221a832e4f7fa64c4fbab3945b6f3af0c5ecd5e16815b328be4954a05fd352256'
                    ],
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d32',
                        'ct' => '142cf1e02d1f58d9285f2af7dcfa44f7c3f2d15c73d460c48c6e0e506a3144bae35284e7e221105b61d24e1c7a'
                    ]
                ]
            ],
        ];
    }

    /**
     * @throws HPKEException
     * @throws SodiumException
     */
    #[DataProvider('rfc9180TestVectors')]
    public function testVectorsRfc9180(HPKE $hpke, array $testVectorsHex, array $encryptions): void
    {
        /** @var MockDHKEM $dhkem */
        $dhkem = $hpke->kem;

        $dhkem->withHPKE($hpke);
        $skEm = sodium_hex2bin($testVectorsHex['skEm']);
        $pkRm = sodium_hex2bin($testVectorsHex['pkRm']);
        $skRm = sodium_hex2bin($testVectorsHex['skRm']);
        $info = sodium_hex2bin($testVectorsHex['info']);
        $dhkem->setPrivateKey($skEm);

        [$enc, $sender] = $hpke->setupBaseSender(new EncapsKey($dhkem->curve, $pkRm), $info);
        $this->assertSame($testVectorsHex['enc'], sodium_bin2hex($enc), 'enc');
        $receiver = $hpke->setupBaseReceiver(new DecapsKey($dhkem->curve, $skRm), $enc, $info);
        foreach ($encryptions as $hexTests) {
            $pt = sodium_hex2bin($hexTests['pt']);
            $ct = sodium_hex2bin($hexTests['ct']);
            $aad = sodium_hex2bin($hexTests['aad']);

            $sealed = $sender->seal($pt, $aad);
            $this->assertSame($hexTests['ct'], sodium_bin2hex($sealed), 'seal');
            $opened = $receiver->open($ct, $aad);
            $this->assertSame($hexTests['pt'], sodium_bin2hex($opened), 'open');
        }
    }
}
