<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests;

use ParagonIE\HPKE\Factory;
use ParagonIE\HPKE\HPKE;
use PHPUnit\Framework\TestCase;

class LabeledKdfTest extends TestCase
{
    private HPKE $hpke;

    public function setUp(): void
    {
        $this->hpke = Factory::dhkem_x25519sha256_hkdf_sha256_aes128gcm();
    }

    public function testLabeledExtractIsDeterministic(): void
    {
        $a = $this->hpke->labeledExtract('ikm', 'label', 'salt');
        $b = $this->hpke->labeledExtract('ikm', 'label', 'salt');
        $this->assertSame(bin2hex($a), bin2hex($b));
    }

    public function testLabeledExpandIsDeterministic(): void
    {
        $prk = $this->hpke->labeledExtract('ikm', 'label', 'salt');
        $a = $this->hpke->labeledExpand($prk, 'label', 'info', 32);
        $b = $this->hpke->labeledExpand($prk, 'label', 'info', 32);
        $this->assertSame(bin2hex($a), bin2hex($b));
        $this->assertSame(32, strlen($a));
    }

    public function testDifferentLabelsProduceDifferentOutput(): void
    {
        $a = $this->hpke->labeledExtract('ikm', 'label-a');
        $b = $this->hpke->labeledExtract('ikm', 'label-b');
        $this->assertNotSame(bin2hex($a), bin2hex($b));
    }
}
