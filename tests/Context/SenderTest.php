<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests\Context;

use ParagonIE\HPKE\Context\Sender;
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\Interfaces\SymmetricKeyInterface;
use ParagonIE\HPKE\Tests\ContextTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SodiumException;

#[CoversClass(Sender::class)]
class SenderTest extends ContextTestCase
{
    public static function makeContext(
        HPKE $hpke,
        SymmetricKeyInterface $key,
        string $baseNonce,
        int $sequence,
        #[\SensitiveParameter] string $exporterSecret,
    ): Sender {
        return new Sender($hpke, $key, $baseNonce, $sequence, $exporterSecret);
    }

    /**
     * @throws HPKEException
     * @throws SodiumException
     */
    #[DataProvider('sealTests')]
    public function testSeal(Sender $sender, array $sequentialOutputs = []): void
    {
        foreach ($sequentialOutputs as $outputs) {
            $pt = sodium_hex2bin($outputs['pt_hex']);
            $aad = sodium_hex2bin($outputs['aad_hex']);
            $sealed = $sender->seal($pt, $aad);
            $this->assertSame($outputs['ct_hex'], sodium_bin2hex($sealed));
            // Sequence number should increase implicitly
        }
    }
}
