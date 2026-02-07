<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests;

use ParagonIE\HPKE\AEAD\{AES128GCM, AES256GCM, ChaCha20Poly1305, ExportOnly};
use ParagonIE\HPKE\{
    Context,
    Hash,
    HPKE,
    HPKEException,
    Interfaces\AEADInterface,
    Interfaces\KDFInterface,
    SymmetricKey,
    Tests\KEM\MockDHKEM,
    Util
};
use ParagonIE\HPKE\Context\{Receiver, Sender};
use ParagonIE\HPKE\KDF\HKDF;
use ParagonIE\HPKE\KEM\{DHKEM\Curve, DHKEM\DecapsKey, DHKEM\EncapsKey, DiffieHellmanKEM};
use PHPUnit\Framework\Attributes\{
    CoversClass,
    DataProvider
};
use PHPUnit\Framework\TestCase;
use SodiumException;

#[CoversClass(HPKE::class)]
#[CoversClass(AES128GCM::class)]
#[CoversClass(AES256GCM::class)]
#[CoversClass(Context::class)]
#[CoversClass(Receiver::class)]
#[CoversClass(Sender::class)]
#[CoversClass(HKDF::class)]
#[CoversClass(Curve::class)]
#[CoversClass(DecapsKey::class)]
#[CoversClass(EncapsKey::class)]
#[CoversClass(DiffieHellmanKEM::class)]
#[CoversClass(SymmetricKey::class)]
#[CoversClass(ChaCha20Poly1305::class)]
#[CoversClass(Util::class)]
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


    public static function rfc9180PSKTestVectors(): array
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
                    'skEm' => '463426a9ffb42bb17dbe6044b9abd1d4e4d95f9041cef0e99d7824eef2b6f588',
                    'pkRm' => '9fed7e8c17387560e92cc6462a68049657246a09bfa8ade7aefe589672016366',
                    'skRm' => 'c5eb01eb457fe6c6f57577c5413b931550a162c71a03ac8d196babbd4e5ce0fd',
                    'psk' => '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82',
                    'psk_id' => '456e6e796e20447572696e206172616e204d6f726961',
                    'enc'  => '0ad0950d9fb9588e59690b74f1237ecdf1d775cd60be2eca57af5a4b0471c91b',
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => 'e52c6fed7f758d0cf7145689f21bc1be6ec9ea097fef4e959440012f4feb73fb611b946199e681f4cfc34db8ea'
                    ],
                ]
            ],
            'DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305' => [
                new HPKE($dhkem_x25519, $kdf_sha256, $chapoly),
                [
                    'info' => '4f6465206f6e2061204772656369616e2055726e',
                    'skEm' => '0c35fdf49df7aa01cd330049332c40411ebba36e0c718ebc3edf5845795f6321',
                    'pkRm' => '13640af826b722fc04feaa4de2f28fbd5ecc03623b317834e7ff4120dbe73062',
                    'skRm' => '77d114e0212be51cb1d76fa99dd41cfd4d0166b08caa09074430a6c59ef17879',
                    'psk' => '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82',
                    'psk_id' => '456e6e796e20447572696e206172616e204d6f726961',
                    'enc'  => '2261299c3f40a9afc133b969a97f05e95be2c514e54f3de26cbe5644ac735b04',
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => '4a177f9c0d6f15cfdf533fb65bf84aecdc6ab16b8b85b4cf65a370e07fc1d78d28fb073214525276f4a89608ff'
                    ],
                ]
            ],
            'DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM' => [
                new HPKE($dhkem_p256, $kdf_sha256, $aes128),
                [
                    'info' => '4f6465206f6e2061204772656369616e2055726e',
                    'skEm' => '57427244f6cc016cddf1c19c8973b4060aa13579b4c067fd5d93a5d74e32a90f',
                    'pkRm' => '040d97419ae99f13007a93996648b2674e5260a8ebd2b822e84899cd52d87446ea394ca76223b76639eccdf00e1967db10ade37db4e7db476261fcc8df97c5ffd1',
                    'skRm' => '438d8bcef33b89e0e9ae5eb0957c353c25a94584b0dd59c991372a75b43cb661',
                    'psk' => '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82',
                    'psk_id' => '456e6e796e20447572696e206172616e204d6f726961',
                    'enc'  => '04305d35563527bce037773d79a13deabed0e8e7cde61eecee403496959e89e4d0ca701726696d1485137ccb5341b3c1c7aaee90a4a02449725e744b1193b53b5f',
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => '90c4deb5b75318530194e4bb62f890b019b1397bbf9d0d6eb918890e1fb2be1ac2603193b60a49c2126b75d0eb'
                    ],
                ]
            ],
            'DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM' => [
                new HPKE($dhkem_p256, $kdf_sha256, $aes128),
                [
                    'info' => '4f6465206f6e2061204772656369616e2055726e',
                    'skEm' => '57427244f6cc016cddf1c19c8973b4060aa13579b4c067fd5d93a5d74e32a90f',
                    'pkRm' => '040d97419ae99f13007a93996648b2674e5260a8ebd2b822e84899cd52d87446ea394ca76223b76639eccdf00e1967db10ade37db4e7db476261fcc8df97c5ffd1',
                    'skRm' => '438d8bcef33b89e0e9ae5eb0957c353c25a94584b0dd59c991372a75b43cb661',
                    'psk' => '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82',
                    'psk_id' => '456e6e796e20447572696e206172616e204d6f726961',
                    'enc'  => '04305d35563527bce037773d79a13deabed0e8e7cde61eecee403496959e89e4d0ca701726696d1485137ccb5341b3c1c7aaee90a4a02449725e744b1193b53b5f',
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => '90c4deb5b75318530194e4bb62f890b019b1397bbf9d0d6eb918890e1fb2be1ac2603193b60a49c2126b75d0eb'
                    ],
                ]
            ],
                        'DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM' => [
                new HPKE($dhkem_p256, $kdf_sha256, $aes128),
                [
                    'info' => '4f6465206f6e2061204772656369616e2055726e',
                    'skEm' => '57427244f6cc016cddf1c19c8973b4060aa13579b4c067fd5d93a5d74e32a90f',
                    'pkRm' => '040d97419ae99f13007a93996648b2674e5260a8ebd2b822e84899cd52d87446ea394ca76223b76639eccdf00e1967db10ade37db4e7db476261fcc8df97c5ffd1',
                    'skRm' => '438d8bcef33b89e0e9ae5eb0957c353c25a94584b0dd59c991372a75b43cb661',
                    'psk' => '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82',
                    'psk_id' => '456e6e796e20447572696e206172616e204d6f726961',
                    'enc'  => '04305d35563527bce037773d79a13deabed0e8e7cde61eecee403496959e89e4d0ca701726696d1485137ccb5341b3c1c7aaee90a4a02449725e744b1193b53b5f',
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => '90c4deb5b75318530194e4bb62f890b019b1397bbf9d0d6eb918890e1fb2be1ac2603193b60a49c2126b75d0eb'
                    ],
                ]
            ],
            'DHKEM(P-256, HKDF-SHA256), HKDF-SHA512, AES-128-GCM' => [
                new HPKE($dhkem_p256, $kdf_sha512, $aes128),
                [
                    'info' => '4f6465206f6e2061204772656369616e2055726e',
                    'skEm' => 'a5901ff7d6931959c2755382ea40a4869b1dec3694ed3b009dda2d77dd488f18',
                    'pkRm' => '043f5266fba0742db649e1043102b8a5afd114465156719cea90373229aabdd84d7f45dabfc1f55664b888a7e86d594853a6cccdc9b189b57839cbbe3b90b55873',
                    'skRm' => 'bc6f0b5e22429e5ff47d5969003f3cae0f4fec50e23602e880038364f33b8522',
                    'psk' => '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82',
                    'psk_id' => '456e6e796e20447572696e206172616e204d6f726961',
                    'enc'  => '04a307934180ad5287f95525fe5bc6244285d7273c15e061f0f2efb211c35057f3079f6e0abae200992610b25f48b63aacfcb669106ddee8aa023feed301901371',
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => '57624b6e320d4aba0afd11f548780772932f502e2ba2a8068676b2a0d3b5129a45b9faa88de39e8306da41d4cc'
                    ],
                ]
            ],
            'DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305' => [
                new HPKE($dhkem_p256, $kdf_sha256, $chapoly),
                [
                    'info' => '4f6465206f6e2061204772656369616e2055726e',
                    'skEm' => '7d6e4e006cee68af9b3fdd583a0ee8962df9d59fab029997ee3f456cbc857904',
                    'pkRm' => '041eb8f4f20ab72661af369ff3231a733672fa26f385ffb959fd1bae46bfda43ad55e2d573b880831381d9367417f554ce5b2134fbba5235b44db465feffc6189e',
                    'skRm' => '12ecde2c8bc2d5d7ed2219c71f27e3943d92b344174436af833337c557c300b3',
                    'psk' => '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82',
                    'psk_id' => '456e6e796e20447572696e206172616e204d6f726961',
                    'enc'  => '04f336578b72ad7932fe867cc4d2d44a718a318037a0ec271163699cee653fa805c1fec955e562663e0c2061bb96a87d78892bff0cc0bad7906c2d998ebe1a7246',
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => '21433eaff24d7706f3ed5b9b2e709b07230e2b11df1f2b1fe07b3c70d5948a53d6fa5c8bed194020bd9df0877b'
                    ],
                ]
            ],
            'DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM' => [
                new HPKE($dhkem_p521, $kdf_sha512, $aes256),
                [
                    'info' => '4f6465206f6e2061204772656369616e2055726e',
                    'skEm' => '012e5cfe0daf5fe2a1cd617f4c4bae7c86f1f527b3207f115e262a98cc65268ec88cb8645aec73b7aa0a472d0292502d1078e762646e0c093cf873243d12c39915f6',
                    'pkRm' => '04006917e049a2be7e1482759fb067ddb94e9c4f7f5976f655088dec45246614ff924ed3b385fc2986c0ecc39d14f907bf837d7306aada59dd5889086125ecd038ead400603394b5d81f89ebfd556a898cc1d6a027e143d199d3db845cb91c5289fb26c5ff80832935b0e8dd08d37c6185a6f77683347e472d1edb6daa6bd7652fea628fae',
                    'skRm' => '011bafd9c7a52e3e71afbdab0d2f31b03d998a0dc875dd7555c63560e142bde264428de03379863b4ec6138f813fa009927dc5d15f62314c56d4e7ff2b485753eb72',
                    'psk' => '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82',
                    'psk_id' => '456e6e796e20447572696e206172616e204d6f726961',
                    'enc'  => '040085eff0835cc84351f32471d32aa453cdc1f6418eaaecf1c2824210eb1d48d0768b368110fab21407c324b8bb4bec63f042cfa4d0868d19b760eb4beba1bff793b30036d2c614d55730bd2a40c718f9466faf4d5f8170d22b6df98dfe0c067d02b349ae4a142e0c03418f0a1479ff78a3db07ae2c2e89e5840f712c174ba2118e90fdcb',
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => 'de69e9d943a5d0b70be3359a19f317bd9aca4a2ebb4332a39bcdfc97d5fe62f3a77702f4822c3be531aa7843a1'
                    ],
                ]
            ],
        ];
    }
    public static function rfc9180AuthTestVectors(): array
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
                    'skEm' => 'ff4442ef24fbc3c1ff86375b0be1e77e88a0de1e79b30896d73411c5ff4c3518',
                    'pkRm' => '1632d5c2f71c2b38d0a8fcc359355200caa8b1ffdf28618080466c909cb69b2e',
                    'skRm' => 'fdea67cf831f1ca98d8e27b1f6abeb5b7745e9d35348b80fa407ff6958f9137e',
                    'pkSm' => '8b0c70873dc5aecb7f9ee4e62406a397b350e57012be45cf53b7105ae731790b',
                    'skSm' => 'dc4a146313cce60a278a5323d321f051c5707e9c45ba21a3479fecdf76fc69dd',
                    'enc'  => '23fb952571a14a25e3d678140cd0e5eb47a0961bb18afcf85896e5453c312e76',
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => '5fd92cc9d46dbf8943e72a07e42f363ed5f721212cd90bcfd072bfd9f44e06b80fd17824947496e21b680c141b'
                    ],
                ]
            ],
            'DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305' => [
                new HPKE($dhkem_x25519, $kdf_sha256, $chapoly),
                [
                    'info' => '4f6465206f6e2061204772656369616e2055726e',
                    'skEm' => 'c94619e1af28971c8fa7957192b7e62a71ca2dcdde0a7cc4a8a9e741d600ab13',
                    'pkRm' => '1a478716d63cb2e16786ee93004486dc151e988b34b475043d3e0175bdb01c44',
                    'skRm' => '3ca22a6d1cda1bb9480949ec5329d3bf0b080ca4c45879c95eddb55c70b80b82',
                    'pkSm' => 'f0f4f9e96c54aeed3f323de8534fffd7e0577e4ce269896716bcb95643c8712b',
                    'skSm' => '2def0cb58ffcf83d1062dd085c8aceca7f4c0c3fd05912d847b61f3e54121f05',
                    'enc'  => 'f7674cc8cd7baa5872d1f33dbaffe3314239f6197ddf5ded1746760bfc847e0e',
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => 'ab1a13c9d4f01a87ec3440dbd756e2677bd2ecf9df0ce7ed73869b98e00c09be111cb9fdf077347aeb88e61bdf'
                    ],
                ]
            ],
            'DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM' => [
                new HPKE($dhkem_p256, $kdf_sha256, $aes128),
                [
                    'info' => '4f6465206f6e2061204772656369616e2055726e',
                    'skEm' => '6b8de0873aed0c1b2d09b8c7ed54cbf24fdf1dfc7a47fa501f918810642d7b91',
                    'pkRm' => '04423e363e1cd54ce7b7573110ac121399acbc9ed815fae03b72ffbd4c18b01836835c5a09513f28fc971b7266cfde2e96afe84bb0f266920e82c4f53b36e1a78d',
                    'skRm' => 'd929ab4be2e59f6954d6bedd93e638f02d4046cef21115b00cdda2acb2a4440e',
                    'pkSm' => '04a817a0902bf28e036d66add5d544cc3a0457eab150f104285df1e293b5c10eef8651213e43d9cd9086c80b309df22cf37609f58c1127f7607e85f210b2804f73',
                    'skSm' => '1120ac99fb1fccc1e8230502d245719d1b217fe20505c7648795139d177f0de9',
                    'enc'  => '042224f3ea800f7ec55c03f29fc9865f6ee27004f818fcbdc6dc68932c1e52e15b79e264a98f2c535ef06745f3d308624414153b22c7332bc1e691cb4af4d53454',
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => '82ffc8c44760db691a07c5627e5fc2c08e7a86979ee79b494a17cc3405446ac2bdb8f265db4a099ed3289ffe19'
                    ],
                ]
            ],
            'DHKEM(P-256, HKDF-SHA256), HKDF-SHA512 AES-128-GCM' => [
                new HPKE($dhkem_p256, $kdf_sha512, $aes128),
                [
                    'info' => '4f6465206f6e2061204772656369616e2055726e',
                    'skEm' => '93cddd5288e7ef4884c8fe321d075df01501b993ff49ffab8184116f39b3c655',
                    'pkRm' => '04378bad519aab406e04d0e5608bcca809c02d6afd2272d4dd03e9357bd0eee8adf84c8deba3155c9cf9506d1d4c8bfefe3cf033a75716cc3cc07295100ec96276',
                    'skRm' => '1ea4484be482bf25fdb2ed39e6a02ed9156b3e57dfb18dff82e4a048de990236',
                    'pkSm' => '0404d3c1f9fca22eb4a6d326125f0814c35593b1da8ea0d11a640730b215a259b9b98a34ad17e21617d19fe1d4fa39a4828bfdb306b729ec51c543caca3b2d9529',
                    'skSm' => '02b266d66919f7b08f42ae0e7d97af4ca98b2dae3043bb7e0740ccadc1957579',
                    'enc'  => '04fec59fa9f76f5d0f6c1660bb179cb314ed97953c53a60ab38f8e6ace60fd59178084d0dd66e0f79172992d4ddb2e91172ce24949bcebfff158dcc417f2c6e9c6',
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => '2480179d880b5f458154b8bfe3c7e8732332de84aabf06fc440f6b31f169e154157fa9eb44f2fa4d7b38a9236e'
                    ],
                ]
            ],
            'DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305' => [
                new HPKE($dhkem_p256, $kdf_sha256, $chapoly),
                [
                    'info' => '4f6465206f6e2061204772656369616e2055726e',
                    'skEm' => '085fd5d5e6ce6497c79df960cac93710006b76217d8bcfafbd2bb2c20ea03c42',
                    'pkRm' => '0444f6ee41818d9fe0f8265bffd016b7e2dd3964d610d0f7514244a60dbb7a11ece876bb110a97a2ac6a9542d7344bf7d2bd59345e3e75e497f7416cf38d296233',
                    'skRm' => '3cb2c125b8c5a81d165a333048f5dcae29a2ab2072625adad66dbb0f48689af9',
                    'pkSm' => '04265529a04d4f46ab6fa3af4943774a9f1127821656a75a35fade898a9a1b014f64d874e88cddb24c1c3d79004d3a587db67670ca357ff4fba7e8b56ec013b98b',
                    'skSm' => '39b19402e742d48d319d24d68e494daa4492817342e593285944830320912519',
                    'enc'  => '040d5176aedba55bc41709261e9195c5146bb62d783031280775f32e507d79b5cbc5748b6be6359760c73cfe10ca19521af704ca6d91ff32fc0739527b9385d415',
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => '25881f219935eec5ba70d7b421f13c35005734f3e4d959680270f55d71e2f5cb3bd2daced2770bf3d9d4916872'
                    ],
                ]
            ],
            'DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM' => [
                new HPKE($dhkem_p521, $kdf_sha512, $aes256),
                [
                    'info' => '4f6465206f6e2061204772656369616e2055726e',
                    'skEm' => '0185f03560de87bb2c543ef03607f3c33ac09980000de25eabe3b224312946330d2e65d192d3b4aa46ca92fc5ca50736b624402d95f6a80dc04d1f10ae9517137261',
                    'pkRm' => '04007d419b8834e7513d0e7cc66424a136ec5e11395ab353da324e3586673ee73d53ab34f30a0b42a92d054d0db321b80f6217e655e304f72793767c4231785c4a4a6e008f31b93b7a4f2b8cd12e5fe5a0523dc71353c66cbdad51c86b9e0bdfcd9a45698f2dab1809ab1b0f88f54227232c858accc44d9a8d41775ac026341564a2d749f4',
                    'skRm' => '013ef326940998544a899e15e1726548ff43bbdb23a8587aa3bef9d1b857338d87287df5667037b519d6a14661e9503cfc95a154d93566d8c84e95ce93ad05293a0b',
                    'pkSm' => '04015cc3636632ea9a3879e43240beae5d15a44fba819282fac26a19c989fafdd0f330b8521dff7dc393101b018c1e65b07be9f5fc9a28a1f450d6a541ee0d76221133001e8f0f6a05ab79f9b9bb9ccce142a453d59c5abebb5674839d935a3ca1a3fbc328539a60b3bc3c05fed22838584a726b9c176796cad0169ba4093332cbd2dc3a9f',
                    'skSm' => '001018584599625ff9953b9305849850d5e34bd789d4b81101139662fbea8b6508ddb9d019b0d692e737f66beae3f1f783e744202aaf6fea01506c27287e359fe776',
                    'enc'  => '04017de12ede7f72cb101dab36a111265c97b3654816dcd6183f809d4b3d111fe759497f8aefdc5dbb40d3e6d21db15bdc60f15f2a420761bcaeef73b891c2b117e9cf01e29320b799bbc86afdc5ea97d941ea1c5bd5ebeeac7a784b3bab524746f3e640ec26ee1bd91255f9330d974f845084637ee0e6fe9f505c5b87c86a4e1a6c3096dd',
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => '0116aeb3a1c405c61b1ce47600b7ecd11d89b9c08c408b7e2d1e00a4d64696d12e6881dc61688209a8207427f9'
                    ],
                ]
            ],
        ];
    }

    public static function rfc9180AuthPSKTestVectors(): array
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
                    'skEm' => '14de82a5897b613616a00c39b87429df35bc2b426bcfd73febcb45e903490768',
                    'pkRm' => '1d11a3cd247ae48e901939659bd4d79b6b959e1f3e7d66663fbc9412dd4e0976',
                    'skRm' => 'cb29a95649dc5656c2d054c1aa0d3df0493155e9d5da6d7e344ed8b6a64a9423',
                    'pkSm' => '2bfb2eb18fcad1af0e4f99142a1c474ae74e21b9425fc5c589382c69b50cc57e',
                    'skSm' => 'fc1c87d2f3832adb178b431fce2ac77c7ca2fd680f3406c77b5ecdf818b119f4',
                    'psk' => '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82',
                    'psk_id' => '456e6e796e20447572696e206172616e204d6f726961',
                    'enc'  => '820818d3c23993492cc5623ab437a48a0a7ca3e9639c140fe1e33811eb844b7c',
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => 'a84c64df1e11d8fd11450039d4fe64ff0c8a99fca0bd72c2d4c3e0400bc14a40f27e45e141a24001697737533e'
                    ],
                ]
            ],
            'DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305' => [
                new HPKE($dhkem_x25519, $kdf_sha256, $chapoly),
                [
                    'info' => '4f6465206f6e2061204772656369616e2055726e',
                    'skEm' => '5e6dd73e82b856339572b7245d3cbb073a7561c0bee52873490e305cbb710410',
                    'pkRm' => 'a5099431c35c491ec62ca91df1525d6349cb8aa170c51f9581f8627be6334851',
                    'skRm' => '7b36a42822e75bf3362dfabbe474b3016236408becb83b859a6909e22803cb0c',
                    'pkSm' => '3ac5bd4dd66ff9f2740bef0d6ccb66daa77bff7849d7895182b07fb74d087c45',
                    'skSm' => '90761c5b0a7ef0985ed66687ad708b921d9803d51637c8d1cb72d03ed0f64418',
                    'psk' => '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82',
                    'psk_id' => '456e6e796e20447572696e206172616e204d6f726961',
                    'enc'  => '656a2e00dc9990fd189e6e473459392df556e9a2758754a09db3f51179a3fc02',
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => '9aa52e29274fc6172e38a4461361d2342585d3aeec67fb3b721ecd63f059577c7fe886be0ede01456ebc67d597'
                    ],
                ]
            ],
            'DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM' => [
                new HPKE($dhkem_p256, $kdf_sha256, $aes128),
                [
                    'info' => '4f6465206f6e2061204772656369616e2055726e',
                    'skEm' => '36f771e411cf9cf72f0701ef2b991ce9743645b472e835fe234fb4d6eb2ff5a0',
                    'pkRm' => '04d824d7e897897c172ac8a9e862e4bd820133b8d090a9b188b8233a64dfbc5f725aa0aa52c8462ab7c9188f1c4872f0c99087a867e8a773a13df48a627058e1b3',
                    'skRm' => 'bdf4e2e587afdf0930644a0c45053889ebcadeca662d7c755a353d5b4e2a8394',
                    'pkSm' => '049f158c750e55d8d5ad13ede66cf6e79801634b7acadcad72044eac2ae1d0480069133d6488bf73863fa988c4ba8bde1c2e948b761274802b4d8012af4f13af9e',
                    'skSm' => 'b0ed8721db6185435898650f7a677affce925aba7975a582653c4cb13c72d240',
                    'psk' => '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82',
                    'psk_id' => '456e6e796e20447572696e206172616e204d6f726961',
                    'enc'  => '046a1de3fc26a3d43f4e4ba97dbe24f7e99181136129c48fbe872d4743e2b131357ed4f29a7b317dc22509c7b00991ae990bf65f8b236700c82ab7c11a84511401',
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => 'b9f36d58d9eb101629a3e5a7b63d2ee4af42b3644209ab37e0a272d44365407db8e655c72e4fa46f4ff81b9246'
                    ],
                ]
            ],
            'DHKEM(P-256, HKDF-SHA256), HKDF-SHA512, AES-128-GCM' => [
                new HPKE($dhkem_p256, $kdf_sha512, $aes128),
                [
                    'info' => '4f6465206f6e2061204772656369616e2055726e',
                    'skEm' => '778f2254ae5d661d5c7fca8c4a7495a25bd13f26258e459159f3899df0de76c1',
                    'pkRm' => '04a4ca7af2fc2cce48edbf2f1700983e927743a4e85bb5035ad562043e25d9a111cbf6f7385fac55edc5c9d2ca6ed351a5643de95c36748e11dbec98730f4d43e9',
                    'skRm' => '00510a70fde67af487c093234fc4215c1cdec09579c4b30cc8e48cb530414d0e',
                    'pkSm' => '04b59a4157a9720eb749c95f842a5e3e8acdccbe834426d405509ac3191e23f2165b5bb1f07a6240dd567703ae75e13182ee0f69fc102145cdb5abf681ff126d60',
                    'skSm' => 'd743b20821e6326f7a26684a4beed7088b35e392114480ca9f6c325079dcf10b',
                    'psk' => '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82',
                    'psk_id' => '456e6e796e20447572696e206172616e204d6f726961',
                    'enc'  => '04801740f4b1b35823f7fb2930eac2efc8c4893f34ba111c0bb976e3c7d5dc0aef5a7ef0bf4057949a140285f774f1efc53b3860936b92279a11b68395d898d138',
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => '840669634db51e28df54f189329c1b727fd303ae413f003020aff5e26276aaa910fc4296828cb9d862c2fd7d16'
                    ],
                ]
            ],
            'DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305' => [
                new HPKE($dhkem_p256, $kdf_sha256, $chapoly),
                [
                    'info' => '4f6465206f6e2061204772656369616e2055726e',
                    'skEm' => '11b7e4de2d919240616a31ab14944cced79bc2372108bb98f6792e3b645fe546',
                    'pkRm' => '04d383fd920c42d018b9d57fd73a01f1eee480008923f67d35169478e55d2e8817068daf62a06b10e0aad4a9e429fa7f904481be96b79a9c231a33e956c20b81b6',
                    'skRm' => 'c29fc577b7e74d525c0043f1c27540a1248e4f2c8d297298e99010a92e94865c',
                    'pkSm' => '0492cf8c9b144b742fe5a63d9a181a19d416f3ec8705f24308ad316564823c344e018bd7c03a33c926bb271b28ef5bf28c0ca00abff249fee5ef7f33315ff34fdb',
                    'skSm' => '53541bd995f874a67f8bfd8038afa67fd68876801f42ff47d0dc2a4deea067ae',
                    'psk' => '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82',
                    'psk_id' => '456e6e796e20447572696e206172616e204d6f726961',
                    'enc'  => '043539917ee26f8ae0aa5f784a387981b13de33124a3cde88b94672030183110f331400115855808244ff0c5b6ca6104483ac95724481d41bdcd9f15b430ad16f6',
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => '9eadfa0f954835e7e920ffe56dec6b31a046271cf71fdda55db72926e1d8fae94cc6280fcfabd8db71eaa65c05'
                    ],
                ]
            ],
            'DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM' => [
                new HPKE($dhkem_p521, $kdf_sha512, $aes256),
                [
                    'info' => '4f6465206f6e2061204772656369616e2055726e',
                    'skEm' => '003430af19716084efeced1241bb1a5625b6c826f11ef31649095eb27952619e36f62a79ea28001ac452fb20ddfbb66e62c6c0b1be03c0d28c97794a1fb638207a83',
                    'pkRm' => '0401655b5d3b7cfafaba30851d25edc44c6dd17d99410efbed8591303b4dbeea8cb1045d5255f9a60384c3bbd4a3386ae6e6fab341dc1f8db0eed5f0ab1aaac6d7838e00dadf8a1c2c64b48f89c633721e88369e54104b31368f26e35d04a442b0b428510fb23caada686add16492f333b0f7ba74c391d779b788df2c38d7a7f4778009d91',
                    'skRm' => '0053c0bc8c1db4e9e5c3e3158bfdd7fc716aef12db13c8515adf821dd692ba3ca53041029128ee19c8556e345c4bcb840bb7fd789f97fe10f17f0e2c6c2528072843',
                    'pkSm' => '040013761e97007293d57de70962876b4926f69a52680b4714bee1d4236aa96c19b840c57e80b14e91258f0a350e3f7ba59f3f091633aede4c7ec4fa8918323aa45d5901076dec8eeb22899fda9ab9e1960003ff0535f53c02c40f2ae4cdc6070a3870b85b4bdd0bb77f1f889e7ee51f465a308f08c666ad3407f75dc046b2ff5a24dbe2ed',
                    'skSm' => '003f64675fc8914ec9e2b3ecf13585b26dbaf3d5d805042ba487a5070b8c5ac1d39b17e2161771cc1b4d0a3ba6e866f4ea4808684b56af2a49b5e5111146d45d9326',
                    'psk' => '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82',
                    'psk_id' => '456e6e796e20447572696e206172616e204d6f726961',
                    'enc'  => '04000a5096a6e6e002c83517b494bfc2e36bfb8632fae8068362852b70d0ff71e560b15aff96741ecffb63d8ac3090c3769679009ac59a99a1feb4713c5f090fc0dbed01ad73c45d29d369e36744e9ed37d12f80700c16d816485655169a5dd66e4ddf27f2acffe0f56f7f77ea2b473b4bf0518b975d9527009a3d14e5a4957e3e8a9074f8',
                ],
                [
                    [
                        'pt' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad' => '436f756e742d30',
                        'ct' => '942a2a92e0817cf032ce61abccf4f3a7c5d21b794ed943227e07b7df2d6dd92c9b8a9371949e65cca262448ab7'
                    ],
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

    /**
     * @throws HPKEException
     * @throws SodiumException
     */
    #[DataProvider('rfc9180PSKTestVectors')]
    public function testPSKVectorsRfc9180(HPKE $hpke, array $testVectorsHex, array $encryptions): void
    {
        /** @var MockDHKEM $dhkem */
        $dhkem = $hpke->kem;

        $dhkem->withHPKE($hpke);
        $skEm = sodium_hex2bin($testVectorsHex['skEm']);
        $pkRm = sodium_hex2bin($testVectorsHex['pkRm']);
        $skRm = sodium_hex2bin($testVectorsHex['skRm']);
        $psk = sodium_hex2bin($testVectorsHex['psk']);
        $psk_id = sodium_hex2bin($testVectorsHex['psk_id']);
        $info = sodium_hex2bin($testVectorsHex['info']);
        $dhkem->setPrivateKey($skEm);

        [$enc, $sender] = $hpke->setupPSKSender(
            new EncapsKey($dhkem->curve, $pkRm),
            $psk,
            $psk_id,
            $info
        );
        $this->assertSame($testVectorsHex['enc'], sodium_bin2hex($enc), 'enc');
        $receiver = $hpke->setupPSKReceiver(
            new DecapsKey($dhkem->curve, $skRm),
            $enc,
            $psk,
            $psk_id,
            $info
        );
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

    /**
     * @throws HPKEException
     * @throws SodiumException
     */
    #[DataProvider('rfc9180AuthTestVectors')]
    public function testAuthVectorsRfc9180(HPKE $hpke, array $testVectorsHex, array $encryptions): void
    {
        /** @var MockDHKEM $dhkem */
        $dhkem = $hpke->kem;

        $dhkem->withHPKE($hpke);
        $skEm = sodium_hex2bin($testVectorsHex['skEm']);
        $pkRm = sodium_hex2bin($testVectorsHex['pkRm']);
        $skRm = sodium_hex2bin($testVectorsHex['skRm']);
        $skSm = sodium_hex2bin($testVectorsHex['skSm']);
        $pkSm = sodium_hex2bin($testVectorsHex['pkSm']);
        $info = sodium_hex2bin($testVectorsHex['info']);
        $dhkem->setPrivateKey($skEm);

        [$enc, $sender] = $hpke->setupAuthSender(
            new EncapsKey($dhkem->curve, $pkRm),
            new DecapsKey($dhkem->curve, $skSm),
            $info
        );
        $this->assertSame($testVectorsHex['enc'], sodium_bin2hex($enc), 'enc');
        $receiver = $hpke->setupAuthReceiver(
            new DecapsKey($dhkem->curve, $skRm),
            new EncapsKey($dhkem->curve, $pkSm),
            $enc,
            $info
        );
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


    /**
     * @throws HPKEException
     * @throws SodiumException
     */
    #[DataProvider('rfc9180AuthPSKTestVectors')]
    public function testAuthPSKVectorsRfc9180(HPKE $hpke, array $testVectorsHex, array $encryptions): void
    {
        /** @var MockDHKEM $dhkem */
        $dhkem = $hpke->kem;

        $dhkem->withHPKE($hpke);
        $skEm = sodium_hex2bin($testVectorsHex['skEm']);
        $pkRm = sodium_hex2bin($testVectorsHex['pkRm']);
        $skRm = sodium_hex2bin($testVectorsHex['skRm']);
        $skSm = sodium_hex2bin($testVectorsHex['skSm']);
        $pkSm = sodium_hex2bin($testVectorsHex['pkSm']);
        $psk = sodium_hex2bin($testVectorsHex['psk']);
        $psk_id = sodium_hex2bin($testVectorsHex['psk_id']);
        $info = sodium_hex2bin($testVectorsHex['info']);
        $dhkem->setPrivateKey($skEm);

        [$enc, $sender] = $hpke->setupAuthPSKSender(
            new EncapsKey($dhkem->curve, $pkRm),
            new DecapsKey($dhkem->curve, $skSm),
            $psk,
            $psk_id,
            $info
        );
        $this->assertSame($testVectorsHex['enc'], sodium_bin2hex($enc), 'enc');
        $receiver = $hpke->setupAuthPSKReceiver(
            new DecapsKey($dhkem->curve, $skRm),
            new EncapsKey($dhkem->curve, $pkSm),
            $enc,
            $psk,
            $psk_id,
            $info
        );

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
