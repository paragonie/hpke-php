<?php
declare(strict_types=1);
namespace ParagonIE\HPKE;

use ParagonIE\HPKE\Interfaces\SymmetricKeyInterface;
use SensitiveParameter;

readonly class SymmetricKey implements SymmetricKeyInterface
{
    public function __construct(
        #[SensitiveParameter] public string $bytes
    ) {}

    public function __debugInfo(): array
    {
        return [];
    }
}
