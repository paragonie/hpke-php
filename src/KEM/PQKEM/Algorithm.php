<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\KEM\PQKEM;

/**
 * Post-quantum KEM algorithms supported in HPKE - KEM IDs from draft-ietf-hpke-pq-03
 */
enum Algorithm: string
{
    case MLKem768 = 'ML-KEM-768';
    case MLKem1024 = 'ML-KEM-1024';
    case XWing = 'X-Wing';

    /**
     * Nenc: Ciphertext length (bytes)
     */
    public function ciphertextLength(): int
    {
        return match ($this) {
            self::MLKem768 => 1088,
            self::MLKem1024 => 1568,
            self::XWing => 1120,
        };
    }

    /**
     * Npk: Encapsulation (public) key length (bytes)
     */
    public function encapsKeyLength(): int
    {
        return match ($this) {
            self::MLKem768 => 1184,
            self::MLKem1024 => 1568,
            self::XWing => 1216,
        };
    }

    /**
     * Nsk: Decapsulation (secret) key length (bytes)
     */
    public function decapsKeyLength(): int
    {
        return match ($this) {
            self::MLKem768, self::MLKem1024 => 64,
            self::XWing => 32,
        };
    }

    public function secretLength(): int
    {
        return 32;
    }

    /**
     * IANA KEM identifier (2 bytes, big-endian)
     */
    public function kemId(): string
    {
        return match ($this) {
            self::MLKem768 => "\x00\x41",
            self::MLKem1024 => "\x00\x42",
            self::XWing => "\x64\x7a",
        };
    }
}
