<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests\AEAD;

use ParagonIE\HPKE\AEAD\AES256GCM;
use ParagonIE\HPKE\Interfaces\SymmetricKeyInterface;
use ParagonIE\HPKE\SymmetricKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass('ParagonIE\HPKE\AEAD\AES256GCM')]
class AES256GCMTest extends TestCase
{
    private AES256GCM $aes;

    public function setUp(): void
    {
        $this->aes = new AES256GCM();
    }

    public static function rfcVectors(): array
    {
        return [
            'DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM' => [
                new SymmetricKey(sodium_hex2bin('751e346ce8f0ddb2305c8a2a85c70d5cf559c53093656be636b9406d4d7d1b70')),
                sodium_hex2bin('55ff7a7d739c69f44b25447b'),
                sodium_hex2bin('4265617574792069732074727574682c20747275746820626561757479'),
                sodium_hex2bin('436f756e742d30'),
                sodium_hex2bin('170f8beddfe949b75ef9c387e201baf4132fa7374593dfafa90768788b'),
                sodium_hex2bin('7b2b200aafcc6d80ea4c795a7c5b841a')
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
