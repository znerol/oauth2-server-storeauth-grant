<?php

declare(strict_types=1);

namespace StoreAuth\JWT\Validation\Constraint;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Lcobucci\JWT\Validation\SignedWith as SignedWithInterface;
use RuntimeException;

/**
 * Check signature with x5c certificate chain.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6
 */

class SignedWithCertificateChain implements SignedWithInterface
{
    /**
     * Temporary directory to use for intermediate certificates.
     */
    private readonly string $tempdir;

    /**
     * @param non-empty-string[] $trustAnchors
     */
    public function __construct(
        private readonly Signer $signer,
        private readonly array $trustAnchors,
        ?string $tempdir = null,
        private readonly string $tempprefix = "x5c"
    ) {
        if ($tempdir === null) {
            $tempdir = sys_get_temp_dir();
        }
        $this->tempdir = $tempdir;
    }

    public function assert(Token $token): void
    {
        if (!$token instanceof UnencryptedToken) {
            throw ConstraintViolation::error("You should pass a plain token", $this);
        }

        if (!$token->headers()->has("x5c")) {
            throw ConstraintViolation::error("Certificate header is missing", $this);
        }

        $chain = $token->headers()->get("x5c");
        if (!is_array($chain) || count($chain) < 1) {
            throw ConstraintViolation::error("Certificate header contains unexpected data", $this);
        }

        $trunk = array_map($this->wrapCert(...), $chain);
        $leaf = array_shift($trunk);

        if (count($trunk) > 0) {
            $trunkFile = tempnam($this->tempdir, $this->tempprefix);
            if ($trunkFile === false) {
                throw new RuntimeException("Failed to create a temporary file while validating certificate chain.");
            }
        } else {
            $trunkFile = null;
        }

        try {
            if ($trunkFile !== null) {
                $writeResult = file_put_contents($trunkFile, implode("\n\n", $trunk));
                if ($writeResult === false) {
                    throw new RuntimeException("An error occured while writing certificate chain to temporary file.");
                }
            }

            $chainResult = openssl_x509_checkpurpose($leaf, X509_PURPOSE_ANY, $this->trustAnchors, $trunkFile);
            if ($chainResult === true) {
                $signedWith = new SignedWith($this->signer, InMemory::plainText($leaf));
                $signedWith->assert($token);
            } elseif ($chainResult === false) {
                throw ConstraintViolation::error("Certificate chain is invalid", $this);
            } else {
                throw new RuntimeException("An error occured while validating certificate chain.");
            }
        } finally {
            if ($trunkFile !== null) {
                @unlink($trunkFile);
            }
        }
    }

    /**
     * @return non-empty-string
     */
    private function wrapCert(string $cert): string
    {
        return implode("\n", [
            "-----BEGIN CERTIFICATE-----",
            $cert,
            "-----END CERTIFICATE-----",
        ]);
    }
}
