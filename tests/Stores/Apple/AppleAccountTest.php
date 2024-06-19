<?php

declare(strict_types=1);

namespace StoreAuth\Tests\Stores\Apple;

use DateInterval;
use DateTimeImmutable;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\JwtFacade;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\HasClaimWithValue;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use StoreAuth\Stores\Apple\AppleAccount;
use StoreAuth\Tests\JWT\Validation\Constraint\HasHeaderWithValue;
use StoreAuth\Tests\KeypairTrait;

#[CoversClass(className: AppleAccount::class)]
final class AppleAccountTest extends TestCase
{
    use KeypairTrait;

    private const TOKEN_PATTERN = '/[a-z0-9-_]+\.[a-z0-9-_]+\.[a-z0-9-_]+/i';

    public function testBearerToken(): void
    {
        $now = new DateTimeImmutable();
        $clock = new FrozenClock($now);

        $kid = "WP6DFAUIQV";
        $iss = "6f49142d-8f9a-41b1-a42c-53c049b3c96c";
        $bid = "com.example.app";
        ["private" => $privateKey, "public" => $publicKey] = $this->generateKeypair(self::EC_KEYPAIR_PARAMS);

        $account = new AppleAccount($kid, $iss, $bid, $privateKey, clock: $clock);

        // First call to getBearerToken() should yield a valid token.
        $bearerToken = $account->getBearerToken();

        $jwt = new JwtFacade();
        $jwt->parse(
            $bearerToken,
            new SignedWith(new Sha256(), InMemory::plainText($publicKey)),
            new StrictValidAt($clock),
            new IssuedBy($iss),
            new PermittedFor("appstoreconnect-v1"),
            new HasClaimWithValue("bid", $bid),
            new HasHeaderWithValue("kid", $kid),
        );
    }

    public function testTokenExpiry(): void
    {
        $now = new DateTimeImmutable();
        $later = $now->add(new DateInterval("PT1S"));
        $expired = $now->add(new DateInterval("PT1H"));
        $clock = $this->createStub(ClockInterface::class);
        $clock->method('now')->willReturn($now, $later, $expired);

        $kid = "WP6DFAUIQV";
        $iss = "6f49142d-8f9a-41b1-a42c-53c049b3c96c";
        $bid = "com.example.app";
        ["private" => $privateKey] = $this->generateKeypair(self::EC_KEYPAIR_PARAMS);

        $account = new AppleAccount($kid, $iss, $bid, $privateKey, clock: $clock);

        // First call to getBearerToken() should yield a valid token.
        $firstToken = $account->getBearerToken();
        $this->assertMatchesRegularExpression(self::TOKEN_PATTERN, $firstToken);

        // Second call to getBearerToken() should yield the same token.
        $secondToken = $account->getBearerToken();
        $this->assertMatchesRegularExpression(self::TOKEN_PATTERN, $secondToken);
        $this->assertSame($firstToken, $secondToken);

        // Third call to getBearerToken() should yield a new token.
        $thirdToken = $account->getBearerToken();
        $this->assertMatchesRegularExpression(self::TOKEN_PATTERN, $thirdToken);
        $this->assertNotEquals($thirdToken, $firstToken);
    }
}
