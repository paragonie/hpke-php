<?php
declare(strict_types=1);
namespace ParagonIE\HPKE;

enum Hash: string
{
    case Sha256 = 'sha256';
    case Sha384 = 'sha384';
    case Sha512 = 'sha512';

    public function getSuiteName(): string
    {
        return match ($this) {
            self::Sha256 => 'SHA256',
            self::Sha384 => 'SHA384',
            self::Sha512 => 'SHA512',
        };
    }
}
