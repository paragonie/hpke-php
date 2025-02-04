<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\AEAD;

use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\Interfaces\AEADInterface;
use ParagonIE\HPKE\Interfaces\KemInterface;
use ParagonIE\HPKE\Interfaces\SymmetricKeyInterface;
use ParagonIE\HPKE\SymmetricKey;

class ExportOnly implements AEADInterface
{
    const AEAD_ID = "\xFF\xFF";

    public function getAeadId(): string
    {
        return self::AEAD_ID;
    }

    /**
     * @throws HPKEException
     */
    public function keyLength(): int
    {
        throw new HPKEException('Export-Only AEAD has no key length');
    }

    /**
     * @throws HPKEException
     */
    public function nonceLength(): int
    {
        throw new HPKEException('Export-Only AEAD has no nonce length');
    }

    /**
     * @throws HPKEException
     */
    public function tagLength(): int
    {
        throw new HPKEException('Export-Only AEAD has no tag length');
    }

    public function export(
        HPKE $hpke,
        SymmetricKeyInterface|string $exporterSecret,
        string $exporterContext,
        int $length
    ): string {
        return $hpke->labeledExpand(
            $exporterSecret,
            $exporterContext,
            'sec',
            $length
        );
    }

    /**
     * @throws HPKEException
     */
    public function encrypt(
        #[\SensitiveParameter] SymmetricKey $key,
        #[\SensitiveParameter] string $plaintext,
        string $nonce,
        string $aad = ''
    ): array {
        throw new HPKEException('Cannot encrypt using Export-Only AEAD');
    }

    /**
     * @throws HPKEException
     */
    public function decrypt(
        #[\SensitiveParameter] SymmetricKey $key,
        string $ciphertext,
        string $tag,
        string $nonce,
        string $aad = ''
    ): string {
        throw new HPKEException('Cannot decrypt using Export-Only AEAD');
    }
}
