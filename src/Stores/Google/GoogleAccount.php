<?php

declare(strict_types=1);

namespace StoreAuth\Stores\Google;

use DateInterval;
use DateTimeImmutable;
use DateTimeInterface;
use DateTimeZone;
use JsonException;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Psr\Clock\ClockInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use RuntimeException;
use StoreAuth\Exceptions\StoreAuthException;
use StoreAuth\Oauth2\ServiceAccount;

/**
 * Implements service account for google play console.
 *
 * @see https://developers.google.com/identity/protocols/oauth2/service-account
 */
final class GoogleAccount implements ServiceAccount
{
    private const AUTH_TOKEN_URL = "https://oauth2.googleapis.com/token";
    private const AUTH_TOKEN_AUDIENCE = "https://oauth2.googleapis.com/token";
    private const AUTH_TOKEN_SCOPE = "https://www.googleapis.com/auth/androidpublisher";

    private string $accessToken = "";
    private DateTimeInterface $accessExpires;

    /**
     * Constructs new google service account from config.
     *
     * @param array{
     *     "client_email": non-empty-string,
     *     "private_key": non-empty-string,
     *     "private_key_id": non-empty-string
     *   } $config Service account configuration as parsed from the json config file.
     */
    public static function fromConfig(
        array $config,
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        ?DateInterval $authTokenTTL = null,
        ?ClockInterface $clock = null,
    ): static {
        return new static(
            kid: $config["private_key_id"],
            iss: $config["client_email"],
            privateKey: $config["private_key"],
            httpClient: $httpClient,
            requestFactory: $requestFactory,
            authTokenTTL: $authTokenTTL ?? new DateInterval("PT600S"),
            clock: $clock ?? new SystemClock(new DateTimeZone(date_default_timezone_get()))
        );
    }

    /**
     * @param non-empty-string $kid
     * @param non-empty-string $iss
     * @param non-empty-string $privateKey
     */
    public function __construct(
        private string $kid,
        private string $iss,
        private string $privateKey,
        private ClientInterface $httpClient,
        private RequestFactoryInterface $requestFactory,
        private DateInterval $authTokenTTL,
        private ClockInterface $clock,
    ) {
        $this->accessExpires = new DateTimeImmutable("@0");
    }

    /**
     * @throws \StoreAuth\Exceptions\StoreAuthException
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

    /**
     * @throws \StoreAuth\Exceptions\StoreAuthException
     */
    private function renewBearerToken(DateTimeImmutable $iat): void
    {
        $key = InMemory::plainText($this->privateKey);
        $config = Configuration::forSymmetricSigner(new Sha256(), $key);

        $authToken = $config->builder()
            ->withHeader("kid", $this->kid)
            ->issuedBy($this->iss)
            ->withClaim("scope", self::AUTH_TOKEN_SCOPE)
            ->permittedFor(self::AUTH_TOKEN_AUDIENCE)
            ->issuedAt($iat)
            ->canOnlyBeUsedAfter($iat)
            ->expiresAt($iat->add($this->authTokenTTL))
            ->getToken($config->signer(), $config->signingKey());

        $authRequest = $this->requestFactory->createRequest("POST", self::AUTH_TOKEN_URL)
            ->withHeader("Content-Type", "application/x-www-form-urlencoded")
            ->withBody(new JwtGrantRequestBody($authToken));
        $authResponse = $this->httpClient->sendRequest($authRequest);
        $responseCode = $authResponse->getStatusCode();
        if ($responseCode !== 200) {
            throw new StoreAuthException("Failed to fetch token from google oauth token endpoint. Response status=$responseCode");
        }

        try {
            $authRecord = json_decode(
                json: $authResponse->getBody()->getContents(),
                associative: true,
                flags: JSON_THROW_ON_ERROR
            );
        } catch (RuntimeException | JsonException $e) {
            throw new StoreAuthException("Failed to parse data returned from google oauth token endpoint.", previous: $e);
        }

        assert(is_array($authRecord));
        assert(is_string($authRecord["access_token"]));
        assert(is_int($authRecord["expires_in"]));

        $this->accessToken = $authRecord["access_token"];
        $accessExpiresIn = intval($authRecord["expires_in"]);
        $this->accessExpires = $iat->add(new DateInterval("PT{$accessExpiresIn}S"));
    }
}
