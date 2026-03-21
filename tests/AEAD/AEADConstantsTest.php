<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests\AEAD;

use ParagonIE\HPKE\AEAD\AES128GCM;
use ParagonIE\HPKE\AEAD\AES256GCM;
use ParagonIE\HPKE\AEAD\ChaCha20Poly1305;
use PHPUnit\Framework\TestCase;

class AEADConstantsTest extends TestCase
{
    public function testAes128GcmConstants(): void
    {
        $aead = new AES128GCM();
        $this->assertSame(16, $aead->keyLength());
        $this->assertSame(12, $aead->nonceLength());
        $this->assertSame(16, $aead->tagLength());
        $this->assertSame("\x00\x01", $aead->getAeadId());
        $this->assertSame('AES-128-GCM', $aead->getSuiteName());
    }

    public function testAes256GcmConstants(): void
    {
        $aead = new AES256GCM();
        $this->assertSame(32, $aead->keyLength());
        $this->assertSame(12, $aead->nonceLength());
        $this->assertSame(16, $aead->tagLength());
        $this->assertSame("\x00\x02", $aead->getAeadId());
        $this->assertSame('AES-256-GCM', $aead->getSuiteName());
    }

    public function testChaCha20Poly1305Constants(): void
    {
        $aead = new ChaCha20Poly1305();
        $this->assertSame(32, $aead->keyLength());
        $this->assertSame(12, $aead->nonceLength());
        $this->assertSame(16, $aead->tagLength());
        $this->assertSame("\x00\x03", $aead->getAeadId());
        $this->assertSame('ChaCha20Poly1305', $aead->getSuiteName());
    }
}
