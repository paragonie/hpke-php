<?php
declare(strict_types=1);
namespace ParagonIE\HPKE;

use ParagonIE\HPKE\Interfaces\SymmetricKeyInterface;
use SodiumException;

abstract class Context
{
    public function __construct(
        protected HPKE                                         $hpke,
        #[\SensitiveParameter] protected SymmetricKeyInterface $key,
        #[\SensitiveParameter] protected string                $baseNonce,
        protected int                                          $sequence,
        #[\SensitiveParameter] protected string                $exporterSecret,
    ) {}

    /**
     * @param string $exporterContext
     * @param int $length
     * @return string
     */
    public function export(string $exporterContext, int $length): string
    {
        return $this->hpke->labeledExpand(
            $this->exporterSecret,
            'sec',
            $exporterContext,
            $length
        );
    }

    /**
     * @return string
     */
    protected function computeNonce(): string
    {
        $seq_bytes = str_pad(
            pack('J', $this->sequence),
            $this->hpke->aead->nonceLength(),
            "\0",
            STR_PAD_LEFT
        );
        return $this->baseNonce ^ $seq_bytes;
    }

    /**
     * @return void
     *
     * @throws HPKEException
     */
    protected function incrementSeq(): void
    {
        $max = PHP_INT_MAX; // (1 << ($this->hpke->aead->nonceLength() * 8)) - 1;
        if ($this->sequence >= $max) {
            throw new HPKEException('Message limit reached');
        }
        ++$this->sequence;
    }
}
