<?php

declare(strict_types=1);

namespace StoreAuth\Stores\Apple;

use DateInterval;
use DateTimeImmutable;
use DateTimeInterface;
use DateTimeZone;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Psr\Clock\ClockInterface;
use StoreAuth\Oauth2\ServiceAccount;

/**
 * Implements service account for apple appstore connect API.
 *
 * @see https://developer.apple.com/documentation/appstoreserverapi/generating_json_web_tokens_for_api_requests
 */
final class AppleAccount implements ServiceAccount
{
    private const AUTH_TOKEN_AUDIENCE = "appstoreconnect-v1";

    private string $accessToken = "";
    private ClockInterface $clock;
    private DateInterval $accessTokenTTL;
    private DateTimeInterface $accessExpires;

    /**
     * Constructs new apple appstore connect service account.
     *
     * @param non-empty-string $kid
     * @param non-empty-string $iss
     * @param non-empty-string $bid
     * @param non-empty-string $privateKey
     */
    public function __construct(
        private string $kid,
        private string $iss,
        private string $bid,
        private string $privateKey,
        ?DateInterval $accessTokenTTL = null,
        ?ClockInterface $clock = null,
    ) {
        $this->accessTokenTTL = $accessTokenTTL ?? new DateInterval("PT600S");
        $this->clock = $clock ?? new SystemClock(new DateTimeZone(date_default_timezone_get()));
        $this->accessExpires = new DateTimeImmutable("@0");
    }

    /**
     * {@inheritdoc}
     */
    public function getBearerToken(): string
    {
        $now = $this->clock->now();
        if ($this->accessExpires < $now) {
            $this->renewBearerToken($now);
        }
        assert(strlen($this->accessToken) > 0);
        return $this->accessToken;
    }

    private function renewBearerToken(DateTimeImmutable $iat): void
    {
        $key = InMemory::plainText($this->privateKey);
        $config = Configuration::forSymmetricSigner(new Sha256(), $key);

        $this->accessExpires = $iat->add($this->accessTokenTTL);
        $this->accessToken = $config->builder()
            ->withHeader("kid", $this->kid)
            ->issuedBy($this->iss)
            ->withClaim("bid", $this->bid)
            ->permittedFor(self::AUTH_TOKEN_AUDIENCE)
            ->issuedAt($iat)
            ->canOnlyBeUsedAfter($iat)
            ->expiresAt($this->accessExpires)
            ->getToken($config->signer(), $config->signingKey())
            ->toString();
    }
}
