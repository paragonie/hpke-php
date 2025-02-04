<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\Context;

use ParagonIE\HPKE\Context;
use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\Role;

class Sender extends Context
{
    const ROLE = Role::Sender;

    /**
     * @throws HPKEException
     */
    public function seal(
        #[\SensitiveParameter] string $plaintext,
        string $aad = ''
    ): string {
        [$ct, $tag] = $this->hpke->aead->encrypt(
            $this->key,
            $plaintext,
            $this->computeNonce(),
            $aad
        );
        $this->incrementSeq();
        return $ct . $tag;
    }
}
