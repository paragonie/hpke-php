<?php
declare(strict_types=1);
namespace ParagonIE\HPKE\KDF;

use ParagonIE\HPKE\{
    Hash,
    SymmetricKey
};
use ParagonIE\HPKE\Interfaces\{
    KDFInterface,
    SymmetricKeyInterface
};
use function hash, hash_hmac;

class HKDF implements KDFInterface
{
    private int $digestLength;
    public function __construct(
        public readonly Hash $hash
    ) {
        $this->digestLength = strlen(
            hash($this->hash->value, '', true)
        );
    }

    public function getHashLength(): int
    {
        return $this->digestLength;
    }

    public function getKdfId(): string
    {
        return match ($this->hash) {
            Hash::Sha256 => "\x00\x01",
            Hash::Sha384 => "\x00\x02",
            Hash::Sha512 => "\x00\x03",
        };
    }

    public function deriveBytes(
        #[\SensitiveParameter]
        string|SymmetricKeyInterface $ikm,
        #[\SensitiveParameter]
        string $info = '',
        #[\SensitiveParameter]
        string $salt = '',
        int $length = 32
    ): string {
        return hash_hkdf(
            $this->hash->value,
            $ikm instanceof SymmetricKeyInterface ? $ikm->bytes : $ikm,
            $length,
            $info,
            $salt
        );
    }

    public function deriveSymmetricKey(
        #[\SensitiveParameter]
        string|SymmetricKeyInterface $ikm,
        #[\SensitiveParameter]
        string $info = '',
        #[\SensitiveParameter]
        string $salt = ''
    ): SymmetricKeyInterface {
        return new SymmetricKey($this->deriveBytes($ikm, $info, $salt));
    }

    public function extract(
        #[\SensitiveParameter]
        string|SymmetricKeyInterface $ikm,
        #[\SensitiveParameter]
        ?string $salt = null
    ): string {
        if (is_null($salt)) {
            $salt = str_repeat("\0", $this->digestLength);
        }
        return hash_hmac(
            $this->hash->value,
            $ikm instanceof SymmetricKeyInterface ? $ikm->bytes : $ikm,
            $salt,
            true
        );
    }

    public function expand(
        #[\SensitiveParameter]
        string|SymmetricKeyInterface $prk,
        #[\SensitiveParameter]
        string $info,
        #[\SensitiveParameter]
        int $length
    ): string {
        $lastBlock = '';
        $t = '';
        for ($index = 1; strlen($t) < $length; ++$index) {
            $lastBlock = hash_hmac(
                $this->hash->value,
                $lastBlock . $info . pack('C', $index),
                $prk instanceof SymmetricKeyInterface ? $prk->bytes : $prk,
                true
            );
            $t .= $lastBlock;
        }
        return substr($t, 0, $length);
    }


    /**
     * @param string $suiteId
     * @param string|SymmetricKeyInterface $ikm
     * @param string $label
     * @param ?string $salt
     * @return string
     */
    public function labeledExtract(
        string $suiteId,
        #[\SensitiveParameter]
        string|SymmetricKeyInterface $ikm,
        #[\SensitiveParameter]
        string $label,
        #[\SensitiveParameter]
        ?string $salt = null
    ): string {
        $labeled_ikm = "HPKE-v1" .
            $suiteId .
            $label .
            ($ikm instanceof SymmetricKeyInterface ? $ikm->bytes : $ikm);
        return $this->extract($labeled_ikm, $salt);
    }

    /**
     * @param string $suiteId
     * @param string|SymmetricKeyInterface $prk
     * @param string $label
     * @param string $info
     * @param int $length
     * @return string
     */
    public function labeledExpand(
        string $suiteId,
        #[\SensitiveParameter] string|SymmetricKeyInterface $prk,
        #[\SensitiveParameter] string $label,
        #[\SensitiveParameter] string $info,
        int $length
    ): string {
        $labeled_info = pack('n', $length) .
            'HPKE-v1' .
            $suiteId .
            $label .
            $info;
        return $this->expand($prk, $labeled_info, $length);
    }

    /**
     * @param string $suiteId
     * @param string $dh
     * @param string $kemContext
     * @param int $length
     * @return string
     */
    public function extractAndExpand(
        string $suiteId,
        #[\SensitiveParameter] string $dh,
        string $kemContext,
        int $length
    ): string {
        return $this->labeledExpand(
            suiteId: $suiteId,
            prk: $this->labeledExtract(
                suiteId: $suiteId,
                ikm: $dh,
                label: 'eae_prk'
            ),
            label: 'shared_secret',
            info: $kemContext,
            length: $length
        );
    }
}
