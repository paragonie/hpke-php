<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests;

use ParagonIE\HPKE\AEAD\ExportOnly;
use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\SymmetricKey;
use PHPUnit\Framework\TestCase;

class ExportOnlyTest extends TestCase
{
    private ExportOnly $aead;

    public function setUp(): void
    {
        $this->aead = new ExportOnly();
    }

    public function testKeyLengthThrows(): void
    {
        $this->expectException(HPKEException::class);
        $this->aead->keyLength();
    }

    public function testNonceLengthThrows(): void
    {
        $this->expectException(HPKEException::class);
        $this->aead->nonceLength();
    }

    public function testTagLengthThrows(): void
    {
        $this->expectException(HPKEException::class);
        $this->aead->tagLength();
    }

    public function testEncryptThrows(): void
    {
        $this->expectException(HPKEException::class);
        $this->aead->encrypt(
            new SymmetricKey(str_repeat("\0", 32)),
            'plaintext',
            str_repeat("\0", 12)
        );
    }

    public function testDecryptThrows(): void
    {
        $this->expectException(HPKEException::class);
        $this->aead->decrypt(
            new SymmetricKey(str_repeat("\0", 32)),
            'ciphertext',
            str_repeat("\0", 16),
            str_repeat("\0", 12)
        );
    }

    public function testAeadId(): void
    {
        $this->assertSame("\xFF\xFF", $this->aead->getAeadId());
    }

    public function testSuiteName(): void
    {
        $this->assertSame('Export-Only AEAD', $this->aead->getSuiteName());
    }
}
