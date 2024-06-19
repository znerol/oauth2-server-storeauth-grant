<?php

declare(strict_types=1);

namespace StoreAuth\Tests\JWT\Validation\Constraint;

use DateTimeImmutable;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\JwtFacade;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Lcobucci\JWT\Signer\Ecdsa\Sha512;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use StoreAuth\JWT\Validation\Constraint\SignedWithCertificateChain;
use StoreAuth\Tests\KeypairTrait;

#[CoversClass(className: SignedWithCertificateChain::class)]
final class SignedWithCertificateChainTest extends TestCase
{
    use KeypairTrait;

    public function testCertificateChain(): void
    {
        // Generate CA certificate.
        $rootKeys = $this->generateKeypair(self::EC_KEYPAIR_PARAMS);
        $rootCert = $this->generateCertificate(
            $rootKeys["keypair"],
            cert_options: ["x509_extensions" => "v3_ca"]
        );

        // Generate intermediate certificate.
        $interKeys = $this->generateKeypair(self::EC_KEYPAIR_PARAMS);
        $interCert = $this->generateCertificate(
            $interKeys["keypair"],
            ca_key: $rootKeys["keypair"],
            ca_cert: $rootCert,
            cert_options: ["x509_extensions" => "v3_ca"]
        );

        // Generate leaf certificate.
        $leafKeys = $this->generateKeypair(self::EC_KEYPAIR_PARAMS);
        $leafCert = $this->generateCertificate(
            $leafKeys["keypair"],
            ca_key: $interKeys["keypair"],
            ca_cert: $interCert,
            csr_options: ["req_extension" => "v3_req"],
        );

        // Build certificate chain.
        $chain = array_map($this->exportCert(...), [$leafCert, $interCert, $rootCert]);

        // Construct a token with x5c claim (certificate chain).
        $facade = new JwtFacade();
        $token = $facade->issue(
            new Sha256(),
            InMemory::plainText($leafKeys["private"]),
            fn (Builder $builder) => $builder->withHeader("x5c", $chain)
        )->toString();

        // Export root certificate file and verify the token using
        // SignedWithCertificateChain.
        $rootCertFile = tempnam(sys_get_temp_dir(), "phpunit");
        try {
            $result = openssl_x509_export_to_file($rootCert, $rootCertFile);
            $this->assertNotFalse($result);

            $facade->parse(
                $token,
                new SignedWithCertificateChain(new Sha256(), [$rootCertFile]),
                new StrictValidAt(new FrozenClock(new DateTimeImmutable())),
            );
        } finally {
            @unlink($rootCertFile);
        }
    }

    public function testSelfSignedCertificate(): void
    {
        // Generate self-signed certificate.
        $keys = $this->generateKeypair(self::EC_KEYPAIR_PARAMS);
        $cert = $this->generateCertificate($keys["keypair"]);

        // Build certificate chain.
        $chain = array_map($this->exportCert(...), [$cert]);

        // Construct a token with x5c claim (containing just the self-signed
        // certificate).
        $facade = new JwtFacade();
        $token = $facade->issue(
            new Sha256(),
            InMemory::plainText($keys["private"]),
            fn (Builder $builder) => $builder->withHeader("x5c", $chain)
        )->toString();

        // Export the self-signed certificate file and verify the token using
        // SignedWithCertificateChain.
        $certFile = tempnam(sys_get_temp_dir(), "phpunit");
        try {
            $result = openssl_x509_export_to_file($cert, $certFile);
            $this->assertNotFalse($result);

            $facade->parse(
                $token,
                new SignedWithCertificateChain(new Sha256(), [$certFile]),
                new StrictValidAt(new FrozenClock(new DateTimeImmutable())),
            );
        } finally {
            @unlink($certFile);
        }
    }

    public function testTrustAnchorBundle(): void
    {
        // Generate self-signed certificate.
        $keys = $this->generateKeypair(self::EC_KEYPAIR_PARAMS);
        $cert = $this->generateCertificate($keys["keypair"]);

        // Build certificate chain.
        $chain = array_map($this->exportCert(...), [$cert]);

        // Construct a token with x5c claim (containing just the self-signed
        // certificate).
        $facade = new JwtFacade();
        $token = $facade->issue(
            new Sha256(),
            InMemory::plainText($keys["private"]),
            fn (Builder $builder) => $builder->withHeader("x5c", $chain)
        )->toString();

        // Generate additional trust anchors.
        $anchors = [
            $this->generateCertificate($this->generateKeypair(self::EC_KEYPAIR_PARAMS)["keypair"]),
            $this->generateCertificate($this->generateKeypair(self::EC_KEYPAIR_PARAMS)["keypair"]),
            $cert,
            $this->generateCertificate($this->generateKeypair(self::EC_KEYPAIR_PARAMS)["keypair"]),
        ];
        // Export the self-signed certificate and the additional trust anchros
        // to a single file and verify the token using
        // SignedWithCertificateChain.
        $certFile = tempnam(sys_get_temp_dir(), "phpunit");
        try {
            foreach ($anchors as $anchor) {
                $pem = "";
                $result = openssl_x509_export($anchor, $pem);
                $this->assertNotFalse($result);
                file_put_contents($certFile, $pem, FILE_APPEND);
            }

            $facade->parse(
                $token,
                new SignedWithCertificateChain(new Sha256(), [$certFile]),
                new StrictValidAt(new FrozenClock(new DateTimeImmutable())),
            );
        } finally {
            @unlink($certFile);
        }
    }

    public function testTrustAnchorIndividualFiles(): void
    {
        // Generate self-signed certificate.
        $keys = $this->generateKeypair(self::EC_KEYPAIR_PARAMS);
        $cert = $this->generateCertificate($keys["keypair"]);

        // Build certificate chain.
        $chain = array_map($this->exportCert(...), [$cert]);

        // Construct a token with x5c claim (containing just the self-signed
        // certificate).
        $facade = new JwtFacade();
        $token = $facade->issue(
            new Sha256(),
            InMemory::plainText($keys["private"]),
            fn (Builder $builder) => $builder->withHeader("x5c", $chain)
        )->toString();

        // Generate additional trust anchors.
        $anchors = [
            $this->generateCertificate($this->generateKeypair(self::EC_KEYPAIR_PARAMS)["keypair"]),
            $this->generateCertificate($this->generateKeypair(self::EC_KEYPAIR_PARAMS)["keypair"]),
            $cert,
            $this->generateCertificate($this->generateKeypair(self::EC_KEYPAIR_PARAMS)["keypair"]),
        ];
        // Export the self-signed certificate and the additional trust anchros
        // to individual files and verify the token using
        // SignedWithCertificateChain.
        $certFiles = [
            tempnam(sys_get_temp_dir(), "phpunit"),
            tempnam(sys_get_temp_dir(), "phpunit"),
            tempnam(sys_get_temp_dir(), "phpunit"),
            tempnam(sys_get_temp_dir(), "phpunit"),
        ];
        try {
            foreach ($anchors as $idx => $anchor) {
                $result = openssl_x509_export_to_file($anchor, $certFiles[$idx]);
                $this->assertNotFalse($result);
            }

            $facade->parse(
                $token,
                new SignedWithCertificateChain(new Sha256(), $certFiles),
                new StrictValidAt(new FrozenClock(new DateTimeImmutable())),
            );
        } finally {
            foreach ($certFiles as $certFile) {
                @unlink($certFile);
            }
        }
    }

    public function testSignatureAndChainMismatch(): void
    {
        // Generate CA certificate.
        $rootKeys = $this->generateKeypair(self::EC_KEYPAIR_PARAMS);
        $rootCert = $this->generateCertificate(
            $rootKeys["keypair"],
            cert_options: ["x509_extensions" => "v3_ca"]
        );

        // Generate intermediate certificate.
        $interKeys = $this->generateKeypair(self::EC_KEYPAIR_PARAMS);
        $interCert = $this->generateCertificate(
            $interKeys["keypair"],
            ca_key: $rootKeys["keypair"],
            ca_cert: $rootCert,
            cert_options: ["x509_extensions" => "v3_ca"]
        );

        // Generate leaf certificate.
        $leafKeys = $this->generateKeypair(self::EC_KEYPAIR_PARAMS);
        $leafCert = $this->generateCertificate(
            $leafKeys["keypair"],
            ca_key: $interKeys["keypair"],
            ca_cert: $interCert,
            csr_options: ["req_extension" => "v3_req"],
        );

        // Build certificate chain.
        $chain = array_map($this->exportCert(...), [$leafCert, $interCert, $rootCert]);

        // Construct a token with x5c claim (certificate chain).
        $facade = new JwtFacade();
        $token = $facade->issue(
            new Sha256(),
            InMemory::plainText($leafKeys["private"]),
            fn (Builder $builder) => $builder->withHeader("x5c", $chain)
        )->toString();

        // Generate additional self-signed certificate (different trust anchor).
        $keys = $this->generateKeypair(self::EC_KEYPAIR_PARAMS);
        $cert = $this->generateCertificate($keys["keypair"]);

        // Export the self-signed certificate file and verify the token using
        // SignedWithCertificateChain.
        $certFile = tempnam(sys_get_temp_dir(), "phpunit");
        try {
            $result = openssl_x509_export_to_file($cert, $certFile);
            $this->assertNotFalse($result);

            $this->expectException(RequiredConstraintsViolated::class);
            $this->expectExceptionMessage("Certificate chain is invalid");
            $facade->parse(
                $token,
                new SignedWithCertificateChain(new Sha256(), [$certFile]),
                new StrictValidAt(new FrozenClock(new DateTimeImmutable())),
            );
        } finally {
            @unlink($certFile);
        }
    }

    public function testMissingCertificateChainClaim(): void
    {
        // Generate self-signed certificate.
        $keys = $this->generateKeypair(self::EC_KEYPAIR_PARAMS);
        $cert = $this->generateCertificate($keys["keypair"]);

        // Construct a token without x5c claim.
        $facade = new JwtFacade();
        $token = $facade->issue(
            new Sha256(),
            InMemory::plainText($keys["private"]),
            fn (Builder $builder) => $builder
        )->toString();

        // Export the self-signed certificate file and verify the token using
        // SignedWithCertificateChain.
        $certFile = tempnam(sys_get_temp_dir(), "phpunit");
        try {
            $result = openssl_x509_export_to_file($cert, $certFile);
            $this->assertNotFalse($result);

            $this->expectException(RequiredConstraintsViolated::class);
            $this->expectExceptionMessage("Certificate header is missing");
            $facade->parse(
                $token,
                new SignedWithCertificateChain(new Sha256(), [$certFile]),
                new StrictValidAt(new FrozenClock(new DateTimeImmutable())),
            );
        } finally {
            @unlink($certFile);
        }
    }

    public function testInvalidCertificateChainClaim(): void
    {
        // Generate self-signed certificate.
        $keys = $this->generateKeypair(self::EC_KEYPAIR_PARAMS);
        $cert = $this->generateCertificate($keys["keypair"]);

        // Construct a token with invalid x5c claim (empty array).
        $facade = new JwtFacade();
        $token = $facade->issue(
            new Sha256(),
            InMemory::plainText($keys["private"]),
            fn (Builder $builder) => $builder->withHeader("x5c", [])
        )->toString();

        // Export the self-signed certificate file and verify the token using
        // SignedWithCertificateChain.
        $certFile = tempnam(sys_get_temp_dir(), "phpunit");
        try {
            $result = openssl_x509_export_to_file($cert, $certFile);
            $this->assertNotFalse($result);

            $this->expectException(RequiredConstraintsViolated::class);
            $this->expectExceptionMessage("Certificate header contains unexpected data");
            $facade->parse(
                $token,
                new SignedWithCertificateChain(new Sha256(), [$certFile]),
                new StrictValidAt(new FrozenClock(new DateTimeImmutable())),
            );
        } finally {
            @unlink($certFile);
        }
    }

    public function testSignerMismatch(): void
    {
        // Generate self-signed certificate.
        $keys = $this->generateKeypair(self::EC_KEYPAIR_PARAMS);
        $cert = $this->generateCertificate($keys["keypair"]);

        // Build certificate chain.
        $chain = array_map($this->exportCert(...), [$cert]);

        // Construct a token with x5c claim (containing just the self-signed
        // certificate).
        $facade = new JwtFacade();
        $token = $facade->issue(
            new Sha256(),
            InMemory::plainText($keys["private"]),
            fn (Builder $builder) => $builder->withHeader("x5c", $chain)
        )->toString();

        // Export the self-signed certificate file and verify the token using
        // SignedWithCertificateChain.
        $certFile = tempnam(sys_get_temp_dir(), "phpunit");
        try {
            $result = openssl_x509_export_to_file($cert, $certFile);
            $this->assertNotFalse($result);

            $this->expectException(RequiredConstraintsViolated::class);
            $this->expectExceptionMessage("Token signer mismatch");
            $facade->parse(
                $token,
                new SignedWithCertificateChain(new Sha512(), [$certFile]),
                new StrictValidAt(new FrozenClock(new DateTimeImmutable())),
            );
        } finally {
            @unlink($certFile);
        }
    }

    /**
     * @param array<non-empty-string, non-empty-string> $dn
     *
     * @param array{
     *      "req_extension"?: non-empty-string
     * } $csr_options
     *
     * @param array{
     *      "x509_extensions"?: non-empty-string
     * } $cert_options
     */
    private function generateCertificate(
        OpenSSLAsymmetricKey $key,
        array $dn = [],
        int $days = 30,
        ?OpenSSLAsymmetricKey $ca_key = null,
        ?OpenSSLCertificate $ca_cert = null,
        array $csr_options = [],
        array $cert_options = []
    ): OpenSSLCertificate {
        $csr = openssl_csr_new($dn, $key, $csr_options);
        $this->assertNotFalse($csr);

        $cert = openssl_csr_sign(
            $csr,
            $ca_cert,
            $ca_key ?? $key,
            $days,
            $cert_options
        );
        $this->assertNotFalse($cert);

        return $cert;
    }

    /**
     * @return non-empty-string
     */
    private function exportCert(OpenSSLCertificate $cert): string
    {
        $result = openssl_x509_export($cert, $pem);
        $this->assertNotFalse($result);

        $count = 0;
        $pem = str_replace(
            ["-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"],
            ["", ""],
            $pem,
            $count,
        );
        $this->assertSame(2, $count);

        $pem = trim($pem);
        $this->assertTrue(strlen($pem) > 0);
        return $pem;
    }
}
