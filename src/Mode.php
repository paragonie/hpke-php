<?php
declare(strict_types=1);
namespace ParagonIE\HPKE;

enum Mode: string
{
    case Base = "\x00";
    case PSK = "\x01";
}
