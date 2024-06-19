<?php

declare(strict_types=1);

namespace StoreAuth\Tests\Stores\Google;

use DateInterval;
use DateTimeImmutable;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\HasClaimWithValue;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use LogicException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use StoreAuth\Exceptions\StoreAuthException;
use StoreAuth\Oauth2\ServiceAccount;
use StoreAuth\Stores\Google\GoogleAccount;
use StoreAuth\Stores\Google\JwtGrantRequestBody;
use StoreAuth\Tests\JWT\Validation\Constraint\HasHeaderWithValue;
use StoreAuth\Tests\KeypairTrait;
use StoreAuth\Tests\PHPUnit\Constraints\IsJwtGrantRequestBody;

#[CoversClass(className: GoogleAccount::class)]
#[UsesClass(className: JwtGrantRequestBody::class)]
final class GoogleAccountTest extends TestCase
{
    use KeypairTrait;

    public function testConstruction(): void
    {
        $config = [
            "type" => "service_account",
            "project_id" => "api-9999999999999999999-999999",
            "private_key_id" => "370ab79b4513eb9bad7c9bd16a95cb76b5b2a56a",
            "private_key" => "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC6R9Z3GWz/zS7t\n[...]\n-----END PRIVATE KEY-----\n",
            "client_email" => "761326798069-r5mljlln1rd4lrbhg75efgigp36m78j5@developer.gserviceaccount.com",
            "client_id" => "999999999999999999999",
            "auth_uri" => "https=>//accounts.google.com/o/oauth2/auth",
            "token_uri" => "https=>//oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url" => "https=>//www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url" => "https=>//www.googleapis.com/robot/v1/metadata/x509/761326798069-r5mljlln1rd4lrbhg75efgigp36m78j5%40developer.gserviceaccount.com",
            "universe_domain" => "googleapis.com"
        ];
        $httpClient = $this->createStub(ClientInterface::class);
        $requestFactory = $this->createStub(RequestFactoryInterface::class);
        $serviceAccount = GoogleAccount::fromConfig($config, $httpClient, $requestFactory);
        $this->assertInstanceOf(ServiceAccount::class, $serviceAccount);
    }

    public function testBearerToken(): void
    {
        $now = new DateTimeImmutable();
        $clock = new FrozenClock($now);

        $kid = "370ab79b4513eb9bad7c9bd16a95cb76b5b2a56a";
        $iss = "761326798069-r5mljlln1rd4lrbhg75efgigp36m78j5@developer.gserviceaccount.com";
        ["private" => $privateKey, "public" => $publicKey] = $this->generateKeypair(self::RSA_KEYPAIR_PARAMS);

        // Setup request and request factory.
        $request = $this->getRequest($iss, $kid, $publicKey, $clock);

        $requestFactory = $this->createMock(RequestFactoryInterface::class);
        $requestFactory->expects($this->once())
            ->method("createRequest")
            ->with("POST", "https://oauth2.googleapis.com/token")
            ->willReturn($request);

        // Setup response body.
        $responseBody = $this->createMock(StreamInterface::class);
        $responseBody->expects($this->once())
            ->method('getContents')
            ->willReturn('{"access_token":"abc","expires_in":600}');

        // Setup response.
        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->once())
            ->method('getStatusCode')
            ->willReturn(200);
        $response->expects($this->once())
            ->method('getBody')
            ->willReturn($responseBody);

        // Setup HTTP client.
        $httpClient = $this->createMock(ClientInterface::class);
        $httpClient->expects($this->once())
            ->method('sendRequest')
            ->with($request)
            ->willReturn($response);

        $account = new GoogleAccount($kid, $iss, $privateKey, $httpClient, $requestFactory, new DateInterval("PT600S"), $clock);
        $actual = $account->getBearerToken();
        $this->assertSame("abc", $actual);

        // Returns the same token without invoking the oauth endpoint as long as
        // it isn't expired.
        $actual = $account->getBearerToken();
        $this->assertSame("abc", $actual);
    }

    public function testTokenExpiry(): void
    {
        $now = new DateTimeImmutable();
        $later = $now->add(new DateInterval("PT1S"));
        $expired = $now->add(new DateInterval("PT1H"));

        $kid = "370ab79b4513eb9bad7c9bd16a95cb76b5b2a56a";
        $iss = "761326798069-r5mljlln1rd4lrbhg75efgigp36m78j5@developer.gserviceaccount.com";
        ["private" => $privateKey, "public" => $publicKey] = $this->generateKeypair(self::RSA_KEYPAIR_PARAMS);

        // Setup request and request factory.
        $initialClock = $this->createStub(ClockInterface::class);
        $initialClock->method('now')->willReturn($now);
        $initialRequest = $this->getRequest($iss, $kid, $publicKey, $initialClock);

        $renewalClock = $this->createStub(ClockInterface::class);
        $renewalClock->method('now')->willReturn($expired);
        $renewalRequest = $this->getRequest($iss, $kid, $publicKey, $renewalClock);

        $requestFactory = $this->createMock(RequestFactoryInterface::class);
        $requestFactory->expects($this->exactly(2))
            ->method("createRequest")
            ->with("POST", "https://oauth2.googleapis.com/token")
            ->willReturn($initialRequest, $renewalRequest);

        // Setup response body.
        $initialBody = $this->createMock(StreamInterface::class);
        $initialBody->expects($this->once())
            ->method('getContents')
            ->willReturn('{"access_token":"abc","expires_in":600}');

        $renewalBody = $this->createMock(StreamInterface::class);
        $renewalBody->expects($this->once())
            ->method('getContents')
            ->willReturn('{"access_token":"efg","expires_in":600}');

        // Setup response.
        $initialResponse = $this->createMock(ResponseInterface::class);
        $initialResponse->expects($this->once())
            ->method('getStatusCode')
            ->willReturn(200);
        $initialResponse->expects($this->once())
            ->method('getBody')
            ->willReturn($initialBody);

        $renewalResponse = $this->createMock(ResponseInterface::class);
        $renewalResponse->expects($this->once())
            ->method('getStatusCode')
            ->willReturn(200);
        $renewalResponse->expects($this->once())
            ->method('getBody')
            ->willReturn($renewalBody);

        // Setup HTTP client.
        $httpClient = $this->createMock(ClientInterface::class);
        $httpClient->expects($this->exactly(2))
            ->method('sendRequest')
            ->willReturnCallback(fn (RequestInterface $request) => match ($request) {
                $initialRequest => $initialResponse,
                $renewalRequest => $renewalResponse,
                default => throw new LogicException()
            });

        $clock = $this->createStub(ClockInterface::class);
        $clock->method('now')->willReturn($now, $later, $expired);
        $account = new GoogleAccount($kid, $iss, $privateKey, $httpClient, $requestFactory, new DateInterval("PT600S"), $clock);

        // First call to getBearerToken() should yield a valid token.
        $firstToken = $account->getBearerToken();
        $this->assertSame("abc", $firstToken);

        // Second call to getBearerToken() should yield the same token.
        $secondToken = $account->getBearerToken();
        $this->assertSame($firstToken, $secondToken);

        // Third call to getBearerToken() should yield a new token.
        $thirdToken = $account->getBearerToken();
        $this->assertSame("efg", $thirdToken);
    }

    public function testTokenExchangeFailure(): void
    {
        $now = new DateTimeImmutable();
        $clock = new FrozenClock($now);

        $kid = "370ab79b4513eb9bad7c9bd16a95cb76b5b2a56a";
        $iss = "761326798069-r5mljlln1rd4lrbhg75efgigp36m78j5@developer.gserviceaccount.com";
        ["private" => $privateKey, "public" => $publicKey] = $this->generateKeypair(self::RSA_KEYPAIR_PARAMS);

        // Setup request and request factory.
        $request = $this->getRequest($iss, $kid, $publicKey, $clock);

        $requestFactory = $this->createMock(RequestFactoryInterface::class);
        $requestFactory->expects($this->once())
            ->method("createRequest")
            ->with("POST", "https://oauth2.googleapis.com/token")
            ->willReturn($request);

        // Setup response.
        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->once())
            ->method('getStatusCode')
            ->willReturn(401);

        // Setup HTTP client.
        $httpClient = $this->createMock(ClientInterface::class);
        $httpClient->expects($this->once())
            ->method('sendRequest')
            ->with($request)
            ->willReturn($response);

        $account = new GoogleAccount($kid, $iss, $privateKey, $httpClient, $requestFactory, new DateInterval("PT600S"), $clock);
        $this->expectException(StoreAuthException::class);
        $this->expectExceptionMessage("Failed to fetch token from google oauth token endpoint. Response status=401");
        $account->getBearerToken();
    }

    public function testInvalidJsonResponse(): void
    {
        $now = new DateTimeImmutable();
        $clock = new FrozenClock($now);

        $kid = "370ab79b4513eb9bad7c9bd16a95cb76b5b2a56a";
        $iss = "761326798069-r5mljlln1rd4lrbhg75efgigp36m78j5@developer.gserviceaccount.com";
        ["private" => $privateKey, "public" => $publicKey] = $this->generateKeypair(self::RSA_KEYPAIR_PARAMS);

        // Setup request and request factory.
        $request = $this->getRequest($iss, $kid, $publicKey, $clock);

        $requestFactory = $this->createMock(RequestFactoryInterface::class);
        $requestFactory->expects($this->once())
            ->method("createRequest")
            ->with("POST", "https://oauth2.googleapis.com/token")
            ->willReturn($request);

        // Setup response body.
        $responseBody = $this->createMock(StreamInterface::class);
        $responseBody->expects($this->once())
            ->method('getContents')
            ->willReturn('{invalid-json[');

        // Setup response.
        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->once())
            ->method('getStatusCode')
            ->willReturn(200);
        $response->expects($this->once())
            ->method('getBody')
            ->willReturn($responseBody);

        // Setup HTTP client.
        $httpClient = $this->createMock(ClientInterface::class);
        $httpClient->expects($this->once())
            ->method('sendRequest')
            ->with($request)
            ->willReturn($response);

        $account = new GoogleAccount($kid, $iss, $privateKey, $httpClient, $requestFactory, new DateInterval("PT600S"), $clock);
        $this->expectException(StoreAuthException::class);
        $this->expectExceptionMessage("Failed to parse data returned from google oauth token endpoint.");
        $account->getBearerToken();
    }

    /**
     * @param non-empty-string $iss
     * @param non-empty-string $kid
     * @param non-empty-string $publicKey
     */
    private function getRequest(string $iss, string $kid, string $publicKey, ClockInterface $clock): RequestInterface&MockObject
    {
        $request = $this->createMock(RequestInterface::class);
        $request->expects($this->once())
            ->method("withHeader")
            ->with("Content-Type", "application/x-www-form-urlencoded")
            ->willReturn($request);
        $request->expects($this->once())
            ->method("withBody")
            ->with(new IsJwtGrantRequestBody(
                new SignedWith(new Sha256(), InMemory::plainText($publicKey)),
                new StrictValidAt($clock),
                new IssuedBy($iss),
                new PermittedFor("https://oauth2.googleapis.com/token"),
                new HasClaimWithValue("scope", "https://www.googleapis.com/auth/androidpublisher"),
                new HasHeaderWithValue("kid", $kid),
            ))
            ->willReturn($request);
        return $request;
    }
}
