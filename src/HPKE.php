<?php
declare(strict_types=1);
namespace ParagonIE\HPKE;

use ParagonIE\HPKE\Context\{
    Receiver,
    Sender
};
use ParagonIE\HPKE\Interfaces\{
    AEADInterface,
    DecapsKeyInterface,
    EncapsKeyInterface,
    KDFInterface,
    KemInterface,
    SymmetricKeyInterface
};
use SensitiveParameter;
use TypeError;

class HPKE
{
    /**
     * @param KemInterface $kem
     * @param KDFInterface $kdf
     * @param AEADInterface $aead
     */
    public function __construct(
        public KemInterface  $kem,
        public KDFInterface  $kdf,
        public AEADInterface $aead
    ) {}

    /**
     * @return string
     */
    public function getSuiteId(): string
    {
        return 'HPKE' .
            $this->kem->getKemId() .
            $this->kdf->getKdfId() .
            $this->aead->getAeadId();
    }

    /**
     * @param EncapsKeyInterface $pk
     * @param string $plaintext
     * @param string $aad
     * @param string $info
     * @return string
     *
     * @throws HPKEException
     */
    public function sealBase(
        EncapsKeyInterface $pk,
        string $plaintext,
        string $aad = '',
        string $info = ''
    ): string {
        [$enc, $ctx] = $this->setupBaseSender($pk, $info);
        return $enc . $ctx->seal($plaintext, $aad);
    }

    /**
     * @param DecapsKeyInterface $sk
     * @param string $ciphertext
     * @param string $aad
     * @param string $info
     * @return string
     * @throws HPKEException
     */
    public function openBase(
        DecapsKeyInterface $sk,
        string $ciphertext,
        string $aad = '',
        string $info = ''
    ): string {
        $len = $this->kem->getHeaderLength();
        $enc = substr($ciphertext, 0, $len);
        $ct = substr($ciphertext, $len);
        $ctx = $this->setupBaseReceiver($sk, $enc, $info);
        return $ctx->open($ct, $aad);
    }

    /**
     * @param EncapsKeyInterface $pk
     * @param string $info
     * @return array{0: string, 1: Sender}
     *
     * @throws HPKEException
     */
    public function setupBaseSender(EncapsKeyInterface $pk, string $info = ''): array
    {
        [$shared_secret, $enc] = $this->kem->withHPKE($this)->encapsulate($pk);
        return [
            $enc,
            $this->keySchedule(Role::Sender, Mode::Base, $shared_secret, $info)
        ];
    }

    /**
     * @param DecapsKeyInterface $sk
     * @param string $enc
     * @param string $info
     * @return Receiver
     *
     * @throws HPKEException
     */
    public function setupBaseReceiver(
        #[SensitiveParameter] DecapsKeyInterface $sk,
        string                                   $enc,
        string                                   $info = ''
    ): Receiver {
        $shared_secret = $this->kem->withHPKE($this)->decapsulate($sk, $enc);
        $recv = $this->keySchedule(Role::Receiver, Mode::Base, $shared_secret, $info);
        if (!$recv instanceof Receiver) {
            throw new TypeError();
        }
        return $recv;
    }

    /**
     * @param EncapsKeyInterface $pk
     * @param string $psk
     * @param string $pskID
     * @param string $info
     * @return array
     *
     * @throws HPKEException
     */
    public function setupPSKSender(
        EncapsKeyInterface           $pk,
        #[SensitiveParameter] string $psk,
        string                       $pskID,
        string                       $info = ''
    ): array {
        [$shared_secret, $enc] = $this->kem->withHPKE($this)->encapsulate($pk);
        return [
            $enc,
            $this->keySchedule(Role::Sender, Mode::PSK, $shared_secret, $info, $psk, $pskID)
        ];
    }

    /**
     * @param DecapsKeyInterface $sk
     * @param string $enc
     * @param string $psk
     * @param string $pskID
     * @param string $info
     * @return Receiver
     *
     * @throws HPKEException
     */
    public function setupPSKReceiver(
        #[SensitiveParameter] DecapsKeyInterface $sk,
        string                                   $enc,
        #[SensitiveParameter] string             $psk,
        string                                   $pskID,
        string                                   $info = ''
    ): Receiver {
        $shared_secret = $this->kem->withHPKE($this)->decapsulate($sk, $enc);
        $recv = $this->keySchedule(Role::Receiver, Mode::PSK, $shared_secret, $info, $psk, $pskID);
        if (!$recv instanceof Receiver) {
            throw new TypeError();
        }
        return $recv;
    }

    /**
     * @param EncapsKeyInterface $pk
     * @param DecapsKeyInterface $sk
     * @param string $info
     * @return array
     *
     * @throws HPKEException
     */
    public function setupAuthSender(
        EncapsKeyInterface                       $pk,
        #[SensitiveParameter] DecapsKeyInterface $sk,
        string                                   $info = ''
    ): array {
        [$shared_secret, $enc] = $this->kem->withHPKE($this)->authEncaps($pk, $sk);
        return [
            $enc,
            $this->keySchedule(Role::Sender, Mode::Auth, $shared_secret, $info)
        ];
    }

    /**
     * @param DecapsKeyInterface $sk
     * @param EncapsKeyInterface $pk
     * @param string $enc
     * @param string $info
     * @return Receiver
     *
     * @throws HPKEException
     */
    public function setupAuthReceiver(
        #[SensitiveParameter] DecapsKeyInterface $sk,
        EncapsKeyInterface                       $pk,
        string                                   $enc,
        string                                   $info = ''
    ): Receiver {
        $shared_secret = $this->kem->withHPKE($this)->authDecaps($sk, $pk, $enc);
        $recv = $this->keySchedule(Role::Receiver, Mode::Auth, $shared_secret, $info);
        if (!$recv instanceof Receiver) {
            throw new TypeError('Expected a receiver, did not get one');
        }
        return $recv;
    }

    public function setupAuthPSKSender(
        EncapsKeyInterface                       $pk,
        #[SensitiveParameter] DecapsKeyInterface $sk,
        #[SensitiveParameter] string             $psk,
        string                                   $pskID,
        string                                   $info = ''
    ): array
    {
        [$shared_secret, $enc] = $this->kem->withHPKE($this)->authEncaps($pk, $sk);
        return [
            $enc,
            $this->keySchedule(Role::Sender, Mode::AuthPSK, $shared_secret, $info, $psk, $pskID)
        ];
    }

    public function setupAuthPSKReceiver(
        #[SensitiveParameter] DecapsKeyInterface $sk,
        EncapsKeyInterface                       $pk,
        string                                   $enc,
        #[SensitiveParameter] string             $psk,
        string                                   $pskID,
        string                                   $info = ''
    ): Receiver {
        $shared_secret = $this->kem->withHPKE($this)->authDecaps($sk, $pk, $enc);
        $recv = $this->keySchedule(Role::Receiver, Mode::Auth, $shared_secret, $info, $psk, $pskID);
        if (!$recv instanceof Receiver) {
            throw new TypeError();
        }
        return $recv;
    }

    /**
     * @param string|SymmetricKeyInterface $ikm
     * @param string $label
     * @param ?string $salt
     * @return string
     */
    public function labeledExtract(
        #[SensitiveParameter] string|SymmetricKeyInterface $ikm,
        #[SensitiveParameter] string                       $label,
        #[SensitiveParameter] ?string                      $salt = null
    ): string {
        return $this->kdf->labeledExtract($this->getSuiteId(), $ikm, $label, $salt);
    }

    /**
     * @param string|SymmetricKeyInterface $prk
     * @param string $label
     * @param string $info
     * @param int $length
     * @return string
     */
    public function labeledExpand(
        #[SensitiveParameter] string|SymmetricKeyInterface $prk,
        #[SensitiveParameter] string                       $label,
        #[SensitiveParameter] string                       $info,
        int                                                $length
    ): string {
        return $this->kdf->labeledExpand($this->getSuiteId(), $prk, $label, $info, $length);
    }

    /**
     * @param string $dh
     * @param string $kemContext
     * @return string
     */
    public function extractAndExpand(
        #[SensitiveParameter] string $dh,
        string                       $kemContext
    ): string {
        return $this->kdf->extractAndExpand(
            $this->getSuiteId(),
            $dh,
            $kemContext,
            $this->aead->keyLength()
        );
    }

    /**
     * @param Role $role
     * @param Mode $mode
     * @param string|SymmetricKeyInterface $sharedSecret
     * @param string $info
     * @param string|SymmetricKeyInterface $psk
     * @param string $pskID
     * @return Context
     *
     * @throws HPKEException
     */
    private function keySchedule(
        Role                                               $role,
        Mode                                               $mode,
        #[SensitiveParameter] string|SymmetricKeyInterface $sharedSecret,
        #[SensitiveParameter] string                       $info = '',
        #[SensitiveParameter] string|SymmetricKeyInterface $psk = '',
        #[SensitiveParameter] string                       $pskID = '',
    ): Context {
        // Coerce string
        $_psk = $psk instanceof SymmetricKeyInterface ? $psk->bytes : $psk;
        $this->verifyPSKInputs($mode, $_psk, $pskID);

        $psk_id_hash = $this->labeledExtract(ikm: $pskID, label: 'psk_id_hash');
        $info_hash = $this->labeledExtract(ikm: $info, label: 'info_hash');
        $key_schedule_context = $mode->value . $psk_id_hash . $info_hash;

        $secret = $this->labeledExtract(
            ikm:  $_psk,
            label: 'secret',
            salt: $sharedSecret instanceof SymmetricKeyInterface
                ? $sharedSecret->bytes
                : $sharedSecret
        );
        $key = new SymmetricKey($this->labeledExpand(
            prk: $secret,
            label: 'key',
            info: $key_schedule_context,
            length: $this->aead->keyLength()
        ));
        $baseNonce = $this->labeledExpand(
            prk: $secret,
            label: 'base_nonce',
            info: $key_schedule_context,
            length: $this->aead->nonceLength()
        );
        $exporterSecret = $this->labeledExpand(
            prk: $secret,
            label: 'exp',
            info: $key_schedule_context,
            length: $this->kdf->getHashLength()
        );
        return match ($role) {
            Role::Receiver => new Receiver(
                $this,
                $key,
                $baseNonce,
                0,
                $exporterSecret
            ),
            Role::Sender => new Sender(
                $this,
                $key,
                $baseNonce,
                0,
                $exporterSecret
            ),
        };
    }

    /**
     * @param Mode $mode
     * @param string $psk
     * @param string $pskId
     * @return void
     *
     * @throws HPKEException
     */
    private function verifyPSKInputs(
        Mode   $mode,
        string $psk = '',
        string $pskId = ''
    ): void {
        $maxLength = (PHP_INT_SIZE << 3) - 1;
        $gotPsk = ~((strlen($psk) - 1) >> $maxLength) & 1;
        $gotPskId = ~((strlen($pskId) - 1) >> $maxLength) & 1;
        if ($gotPsk !== $gotPskId) {
            throw new HPKEException('Inconsistent PSK Inputs');
        }
        if ($gotPsk && in_array($mode, [Mode::Base, Mode::Auth])) {
            throw new HPKEException('PSK input provided when not needed');
        }
        if (!$gotPskId && in_array($mode, [Mode::PSK, Mode::AuthPSK])) {
            throw new HPKEException('Missing required PSK input');
        }
    }
}
