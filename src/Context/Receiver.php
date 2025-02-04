<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Context;
use ParagonIE\HPKE\Context;
use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\Role;

class Receiver extends Context
{
    const ROLE = Role::Receiver;

    /**
     * @throws HPKEException
     */
    public function open(
        string $ciphertext,
        string $aad = ''
    ): string {
        $Nt = $this->hpke->aead->tagLength();
        $ct = substr($ciphertext, 0, -$Nt);
        $tag = substr($ciphertext, -$Nt, $Nt);
        $pt = $this->hpke->aead->decrypt(
            $this->key,
            $ct,
            $tag,
            $this->computeNonce(),
            $aad
        );
        $this->incrementSeq();
        return $pt;
    }
}
