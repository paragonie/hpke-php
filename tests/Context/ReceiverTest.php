<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Tests\Context;

use ParagonIE\HPKE\Context\Receiver;
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\Interfaces\SymmetricKeyInterface;
use ParagonIE\HPKE\Tests\ContextTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SodiumException;

#[CoversClass(Receiver::class)]
class ReceiverTest extends ContextTestCase
{
    public static function makeContext(
        HPKE $hpke,
        SymmetricKeyInterface $key,
        string $baseNonce,
        int $sequence,
        #[\SensitiveParameter] string $exporterSecret,
    ): Receiver {
        return new Receiver($hpke, $key, $baseNonce, $sequence, $exporterSecret);
    }

    /**
     * @throws HPKEException
     * @throws SodiumException
     */
    #[DataProvider('sealTests')]
    public function testReceive(Receiver $receiver, array $sequentialOutputs = []): void
    {
        foreach ($sequentialOutputs as $outputs) {
            $ct = sodium_hex2bin($outputs['ct_hex']);
            $aad = sodium_hex2bin($outputs['aad_hex']);
            $opened = $receiver->open($ct, $aad);
            $this->assertSame($outputs['pt_hex'], sodium_bin2hex($opened));
            // Sequence number should increase implicitly
        }
    }
}
