<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests\KEM;

use Mdanter\Ecc\Exception\InsecureCurveException;
use ParagonIE\EasyECC\Exception\NotImplementedException;
use ParagonIE\HPKE\AEAD\{
    AES128GCM,
    AES256GCM,
    ChaCha20Poly1305,
    ExportOnly
};
use ParagonIE\HPKE\Hash;
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\Interfaces\AEADInterface;
use ParagonIE\HPKE\Interfaces\KDFInterface;
use ParagonIE\HPKE\KDF\HKDF;
use ParagonIE\HPKE\KEM\DHKEM\Curve;
use ParagonIE\HPKE\KEM\DHKEM\EncapsKey;
use ParagonIE\HPKE\KEM\DiffieHellmanKEM;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SodiumException;

#[CoversClass(DiffieHellmanKEM::class)]
class DiffieHellmanKEMTest extends TestCase
{
    public static function rfc9180provider(): array
    {
        return [
            [
                new MockDHKEM(Curve::X25519, new HKDF(Hash::Sha256)),
                new HKDF(Hash::Sha256),
                new AES128GCM(),
                [
                    'skEm' => '52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736',
                    'pkRm' => '3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d',
                    'skRm' => '4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8',
                    'enc'  => '37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431',
                    'shared_secret' => 'fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc',
                ]
            ],
            [
                new MockDHKEM(Curve::X25519, new HKDF(Hash::Sha256)),
                new HKDF(Hash::Sha256),
                new ChaCha20Poly1305(),
                [
                    'skEm' => 'f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600',
                    'pkRm' => '4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a',
                    'skRm' => '8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb',
                    'enc'  => '1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a',
                    'shared_secret' => '0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7',
                ],
            ],
            [
                new MockDHKEM(Curve::NistP256, new HKDF(Hash::Sha256)),
                new HKDF(Hash::Sha256),
                new AES128GCM(),
                [
                    'skEm' => '4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb',
                    'pkRm' => '04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0',
                    'skRm' => 'f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2',
                    'enc'  => '04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4',
                    'shared_secret' => 'c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8',
                ],
            ],
            [
                new MockDHKEM(Curve::NistP256, new HKDF(Hash::Sha256)),
                new HKDF(Hash::Sha512),
                new AES128GCM(),
                [
                    'skEm' => '2292bf14bb6e15b8c81a0f45b7a6e93e32d830e48cca702e0affcfb4d07e1b5c',
                    'pkRm' => '04085aa5b665dc3826f9650ccbcc471be268c8ada866422f739e2d531d4a8818a9466bc6b449357096232919ec4fe9070ccbac4aac30f4a1a53efcf7af90610edd',
                    'skRm' => '3ac8530ad1b01885960fab38cf3cdc4f7aef121eaa239f222623614b4079fb38',
                    'enc'  => '0493ed86735bdfb978cc055c98b45695ad7ce61ce748f4dd63c525a3b8d53a15565c6897888070070c1579db1f86aaa56deb8297e64db7e8924e72866f9a472580',
                    'shared_secret' => '02f584736390fc93f5b4ad039826a3fa08e9911bd1215a3db8e8791ba533cafd',
                ],
            ],
            [
                new MockDHKEM(Curve::NistP256, new HKDF(Hash::Sha256)),
                new HKDF(Hash::Sha256),
                new ChaCha20Poly1305(),
                [
                    'skEm' => '7550253e1147aae48839c1f8af80d2770fb7a4c763afe7d0afa7e0f42a5b3689',
                    'pkRm' => '04a697bffde9405c992883c5c439d6cc358170b51af72812333b015621dc0f40bad9bb726f68a5c013806a790ec716ab8669f84f6b694596c2987cf35baba2a006',
                    'skRm' => 'a4d1c55836aa30f9b3fbb6ac98d338c877c2867dd3a77396d13f68d3ab150d3b',
                    'enc'  => '04c07836a0206e04e31d8ae99bfd549380b072a1b1b82e563c935c095827824fc1559eac6fb9e3c70cd3193968994e7fe9781aa103f5b50e934b5b2f387e381291',
                    'shared_secret' => '806520f82ef0b03c823b7fc524b6b55a088f566b9751b89551c170f4113bd850',
                ],
            ],
            [
                new MockDHKEM(Curve::NistP521, new HKDF(Hash::Sha512)),
                new HKDF(Hash::Sha512),
                new AES256GCM(),
                [
                    'skEm' => '014784c692da35df6ecde98ee43ac425dbdd0969c0c72b42f2e708ab9d535415a8569bdacfcc0a114c85b8e3f26acf4d68115f8c91a66178cdbd03b7bcc5291e374b',
                    'pkRm' => '0401b45498c1714e2dce167d3caf162e45e0642afc7ed435df7902ccae0e84ba0f7d373f646b7738bbbdca11ed91bdeae3cdcba3301f2457be452f271fa6837580e661012af49583a62e48d44bed350c7118c0d8dc861c238c72a2bda17f64704f464b57338e7f40b60959480c0e58e6559b190d81663ed816e523b6b6a418f66d2451ec64',
                    'skRm' => '01462680369ae375e4b3791070a7458ed527842f6a98a79ff5e0d4cbde83c27196a3916956655523a6a2556a7af62c5cadabe2ef9da3760bb21e005202f7b2462847',
                    'enc'  => '040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8900aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed0692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0',
                    'shared_secret' => '776ab421302f6eff7d7cb5cb1adaea0cd50872c71c2d63c30c4f1d5e43653336fef33b103c67e7a98add2d3b66e2fda95b5b2a667aa9dac7e59cc1d46d30e818',
                ],
            ],
            [
                new MockDHKEM(Curve::X25519, new HKDF(Hash::Sha256)),
                new HKDF(Hash::Sha256),
                new ExportOnly(),
                [
                    'skEm' => '095182b502f1f91f63ba584c7c3ec473d617b8b4c2cec3fad5af7fa6748165ed',
                    'pkRm' => '194141ca6c3c3beb4792cd97ba0ea1faff09d98435012345766ee33aae2d7664',
                    'skRm' => '33d196c830a12f9ac65d6e565a590d80f04ee9b19c83c87f2c170d972a812848',
                    'enc'  => 'e5e8f9bfff6c2f29791fc351d2c25ce1299aa5eaca78a757c0b4fb4bcd830918',
                    'shared_secret' => 'e81716ce8f73141d4f25ee9098efc968c91e5b8ce52ffff59d64039e82918b66',
                ]
            ]
        ];
    }

    /**
     * @throws InsecureCurveException
     * @throws NotImplementedException
     * @throws HPKEException
     * @throws SodiumException
     */
    #[DataProvider('rfc9180provider')]
    public function testRfc9180(MockDHKEM $dhkem, KDFInterface $kdf, AEADInterface $aead, array $testVectorsHex): void
    {
        $hpke = new HPKE($dhkem, $kdf, $aead);
        $dhkem->withHPKE($hpke);
        $skEm = sodium_hex2bin($testVectorsHex['skEm']);
        $pkRm = sodium_hex2bin($testVectorsHex['pkRm']);
        $dhkem->setPrivateKey($skEm);
        [$shared_secret, $enc] = $dhkem->encapsulate(new EncapsKey($dhkem->curve, $pkRm));
        $this->assertSame($testVectorsHex['enc'], sodium_bin2hex($enc), 'enc');
        $this->assertSame(
            $testVectorsHex['shared_secret'],
            sodium_bin2hex($shared_secret->bytes),
            'shared_secret'
        );
    }
}
