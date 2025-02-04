<?php

namespace ParagonIE\HPKE\Tests;

use ParagonIE\HPKE\AEAD\{
    AES128GCM,
    AES256GCM,
    ChaCha20Poly1305
};
use ParagonIE\HPKE\Context;
use ParagonIE\HPKE\Hash;
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\Interfaces\SymmetricKeyInterface;
use ParagonIE\HPKE\KDF\HKDF;
use ParagonIE\HPKE\KEM\DHKEM\Curve;
use ParagonIE\HPKE\KEM\DiffieHellmanKEM;
use ParagonIE\HPKE\SymmetricKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SodiumException;

#[CoversClass(Context::class)]
abstract class ContextTestCase extends TestCase
{
    /**
     * @ref https://www.rfc-editor.org/rfc/rfc9180.html#name-test-vectors
     * @throws SodiumException
     */
    public static function sealTests(): array
    {
        $dhkem_x25519_aes128gcm = new HPKE(
            new DiffieHellmanKEM(Curve::X25519, new HKDF(Hash::Sha256)),
            new HKDF(Hash::Sha256),
            new AES128GCM()
        );
        $dhkem_x25519_chapoly = new HPKE(
            new DiffieHellmanKEM(Curve::X25519, new HKDF(Hash::Sha256)),
            new HKDF(Hash::Sha256),
            new ChaCha20Poly1305()
        );
        $dhkem_p256_aes128gcm = new HPKE(
            new DiffieHellmanKEM(Curve::NistP256, new HKDF(Hash::Sha256)),
            new HKDF(Hash::Sha256),
            new AES128GCM()
        );
        $dhkem_p256_aes128gcm_mismatch = new HPKE(
            new DiffieHellmanKEM(Curve::NistP256, new HKDF(Hash::Sha256)),
            new HKDF(Hash::Sha512),
            new AES128GCM()
        );
        $dhkem_p256_chapoly = new HPKE(
            new DiffieHellmanKEM(Curve::NistP256, new HKDF(Hash::Sha256)),
            new HKDF(Hash::Sha256),
            new ChaCha20Poly1305()
        );
        $dhkem_p521_aes256gcm = new HPKE(
            new DiffieHellmanKEM(Curve::NistP521, new HKDF(Hash::Sha512)),
            new HKDF(Hash::Sha512),
            new AES256GCM()
        );
        return [
            'DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM' => [
                static::makeContext(
                    $dhkem_x25519_aes128gcm,
                    new SymmetricKey(sodium_hex2bin('4531685d41d65f03dc48f6b8302c05b0')),
                    sodium_hex2bin('56d890e5accaaf011cff4b7d'),
                    0,
                    sodium_hex2bin('45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8'),
                ),
                [
                    [
                        'pt_hex' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad_hex' => '436f756e742d30',
                        'ct_hex' => 'f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a'
                    ],
                    [
                        'pt_hex' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad_hex' => '436f756e742d31',
                        'ct_hex' => 'af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84'
                    ],
                    [
                        'pt_hex' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad_hex' => '436f756e742d32',
                        'ct_hex' => '498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180'
                    ]
                ]
            ],
            'DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305' => [
                static::makeContext(
                    $dhkem_x25519_chapoly,
                    new SymmetricKey(sodium_hex2bin('ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91')),
                    sodium_hex2bin('5c4d98150661b848853b547f'),
                    0,
                    sodium_hex2bin('a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922'),
                ),
                [
                    [
                        'pt_hex' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad_hex' => '436f756e742d30',
                        'ct_hex' => '1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28'
                    ],
                    [
                        'pt_hex' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad_hex' => '436f756e742d31',
                        'ct_hex' => '6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c'
                    ],
                    [
                        'pt_hex' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad_hex' => '436f756e742d32',
                        'ct_hex' => '71146bd6795ccc9c49ce25dda112a48f202ad220559502cef1f34271e0cb4b02b4f10ecac6f48c32f878fae86b'
                    ]
                ]
            ],
            'DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM' => [
                static::makeContext(
                    $dhkem_p256_aes128gcm,
                    new SymmetricKey(sodium_hex2bin('868c066ef58aae6dc589b6cfdd18f97e')),
                    sodium_hex2bin('4e0bc5018beba4bf004cca59'),
                    0,
                    sodium_hex2bin('14ad94af484a7ad3ef40e9f3be99ecc6fa9036df9d4920548424df127ee0d99f'),
                ),
                [
                    [
                        'pt_hex' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad_hex' => '436f756e742d30',
                        'ct_hex' => '5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434'
                    ],
                    [
                        'pt_hex' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad_hex' => '436f756e742d31',
                        'ct_hex' => 'fa6f037b47fc21826b610172ca9637e82d6e5801eb31cbd3748271affd4ecb06646e0329cbdf3c3cd655b28e82'
                    ],
                    [
                        'pt_hex' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad_hex' => '436f756e742d32',
                        'ct_hex' => '895cabfac50ce6c6eb02ffe6c048bf53b7f7be9a91fc559402cbc5b8dcaeb52b2ccc93e466c28fb55fed7a7fec'
                    ]
                ]
            ],
            'DHKEM(P-256, HKDF-SHA256), HKDF-SHA512, AES-128-GCM' => [
                static::makeContext(
                    $dhkem_p256_aes128gcm_mismatch,
                    new SymmetricKey(sodium_hex2bin('090ca96e5f8aa02b69fac360da50ddf9')),
                    sodium_hex2bin('9c995e621bf9a20c5ca45546'),
                    0,
                    sodium_hex2bin('4a7abb2ac43e6553f129b2c5750a7e82d149a76ed56dc342d7bca61e26d494f4855dff0d0165f27ce57756f7f16baca006539bb8e4518987ba610480ac03efa8'),
                ),
                [
                    [
                        'pt_hex' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad_hex' => '436f756e742d30',
                        'ct_hex' => 'd3cf4984931484a080f74c1bb2a6782700dc1fef9abe8442e44a6f09044c88907200b332003543754eb51917ba'
                    ],
                    [
                        'pt_hex' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad_hex' => '436f756e742d31',
                        'ct_hex' => 'd14414555a47269dfead9fbf26abb303365e40709a4ed16eaefe1f2070f1ddeb1bdd94d9e41186f124e0acc62d'
                    ],
                    [
                        'pt_hex' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad_hex' => '436f756e742d32',
                        'ct_hex' => '9bba136cade5c4069707ba91a61932e2cbedda2d9c7bdc33515aa01dd0e0f7e9d3579bf4016dec37da4aafa800'
                    ]
                ]
            ],
            'DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305' => [
                static::makeContext(
                    $dhkem_p256_chapoly,
                    new SymmetricKey(sodium_hex2bin('a8f45490a92a3b04d1dbf6cf2c3939ad8bfc9bfcb97c04bffe116730c9dfe3fc')),
                    sodium_hex2bin('726b4390ed2209809f58c693'),
                    0,
                    sodium_hex2bin('4f9bd9b3a8db7d7c3a5b9d44fdc1f6e37d5d77689ade5ec44a7242016e6aa205'),
                ),
                [
                    [
                        'pt_hex' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad_hex' => '436f756e742d30',
                        'ct_hex' => '6469c41c5c81d3aa85432531ecf6460ec945bde1eb428cb2fedf7a29f5a685b4ccb0d057f03ea2952a27bb458b'
                    ],
                    [
                        'pt_hex' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad_hex' => '436f756e742d31',
                        'ct_hex' => 'f1564199f7e0e110ec9c1bcdde332177fc35c1adf6e57f8d1df24022227ffa8716862dbda2b1dc546c9d114374'
                    ],
                    [
                        'pt_hex' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad_hex' => '436f756e742d32',
                        'ct_hex' => '39de89728bcb774269f882af8dc5369e4f3d6322d986e872b3a8d074c7c18e8549ff3f85b6d6592ff87c3f310c'
                    ]
                ]
            ],
            'DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM' => [
                static::makeContext(
                    $dhkem_p521_aes256gcm,
                    new SymmetricKey(sodium_hex2bin('751e346ce8f0ddb2305c8a2a85c70d5cf559c53093656be636b9406d4d7d1b70')),
                    sodium_hex2bin('55ff7a7d739c69f44b25447b'),
                    0,
                    sodium_hex2bin('e4ff9dfbc732a2b9c75823763c5ccc954a2c0648fc6de80a58581252d0ee3215388a4455e69086b50b87eb28c169a52f42e71de4ca61c920e7bd24c95cc3f992'),
                ),
                [
                    [
                        'pt_hex' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad_hex' => '436f756e742d30',
                        'ct_hex' => '170f8beddfe949b75ef9c387e201baf4132fa7374593dfafa90768788b7b2b200aafcc6d80ea4c795a7c5b841a'
                    ],
                    [
                        'pt_hex' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad_hex' => '436f756e742d31',
                        'ct_hex' => 'd9ee248e220ca24ac00bbbe7e221a832e4f7fa64c4fbab3945b6f3af0c5ecd5e16815b328be4954a05fd352256'
                    ],
                    [
                        'pt_hex' => '4265617574792069732074727574682c20747275746820626561757479',
                        'aad_hex' => '436f756e742d32',
                        'ct_hex' => '142cf1e02d1f58d9285f2af7dcfa44f7c3f2d15c73d460c48c6e0e506a3144bae35284e7e221105b61d24e1c7a'
                    ]
                ]
            ],
        ];
    }

    abstract public static function makeContext(
        HPKE $hpke,
        SymmetricKeyInterface $key,
        string $baseNonce,
        int $sequence,
        #[\SensitiveParameter] string $exporterSecret,
    ): Context;
}
