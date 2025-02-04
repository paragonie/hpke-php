<?php
declare(strict_types=1);
namespace ParagonIE\HPKE;

enum Hash: string
{
    case Sha256 = 'sha256';
    case Sha384 = 'sha384';
    case Sha512 = 'sha512';
}
