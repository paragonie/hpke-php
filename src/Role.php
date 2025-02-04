<?php
declare(strict_types=1);
namespace ParagonIE\HPKE;

enum Role : string
{
    case Sender = 'S';
    case Receiver = 'R';
}
