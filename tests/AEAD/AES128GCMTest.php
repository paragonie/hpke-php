<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests\AEAD;

use ParagonIE\HPKE\AEAD\AES128GCM;
use ParagonIE\HPKE\Interfaces\SymmetricKeyInterface;
use ParagonIE\HPKE\SymmetricKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass('ParagonIE\HPKE\AEAD\AES128GCM')]
class AES128GCMTest extends TestCase
{
    private AES128GCM $aes;

    public function setUp(): void
    {
        $this->aes = new AES128GCM();
    }

    public static function rfcVectors(): array
    {
        return [
            'DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM' => [
                new SymmetricKey(sodium_hex2bin('4531685d41d65f03dc48f6b8302c05b0')),
                sodium_hex2bin('56d890e5accaaf011cff4b7d'),
                sodium_hex2bin('4265617574792069732074727574682c20747275746820626561757479'),
                sodium_hex2bin('436f756e742d30'),
                sodium_hex2bin('f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218'),
                sodium_hex2bin('a355a96d8770ac83d07bea87e13c512a')
            ]
        ];
    }

    #[DataProvider('rfcVectors')]
    public function testVector(
        SymmetricKeyInterface $key,
        string $nonce,
        string $plaintexxt,
        string $aad,
        string $ciphertext,
        string $tag
    ) {
        [$actual_ct, $actual_tag] = $this->aes->encrypt($key, $plaintexxt, $nonce, $aad);
        $this->assertSame($ciphertext, $actual_ct, 'Ciphertext');
        $this->assertSame($tag, $actual_tag, 'Authentication tag');
        $decrypt = $this->aes->decrypt($key, $ciphertext, $tag, $nonce, $aad);
        $this->assertSame($plaintexxt, $decrypt, 'Decryption');
    }
}
