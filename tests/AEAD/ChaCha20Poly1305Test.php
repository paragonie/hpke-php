<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests\AEAD;

use ParagonIE\HPKE\AEAD\ChaCha20Poly1305;
use ParagonIE\HPKE\Interfaces\SymmetricKeyInterface;
use ParagonIE\HPKE\SymmetricKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass('ParagonIE\HPKE\AEAD\ChaCha20Poly1305')]
class ChaCha20Poly1305Test extends TestCase
{
    private ChaCha20Poly1305 $aes;

    public function setUp(): void
    {
        $this->aes = new ChaCha20Poly1305();
    }

    public static function rfcVectors(): array
    {
        return [
            'DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305' => [
                new SymmetricKey(sodium_hex2bin('ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91')),
                sodium_hex2bin('5c4d98150661b848853b547f'),
                sodium_hex2bin('4265617574792069732074727574682c20747275746820626561757479'),
                sodium_hex2bin('436f756e742d30'),
                sodium_hex2bin('1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b'),
                sodium_hex2bin('60b4db21993c62ce81883d2dd1b51a28')
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
