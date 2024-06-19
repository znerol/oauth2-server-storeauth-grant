<?php

declare(strict_types=1);

namespace StoreAuth\Tests\Stores\Apple;

use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use StoreAuth\Exceptions\StoreAuthException;
use StoreAuth\Oauth2\ServiceAccount;
use StoreAuth\Stores\Apple\MostRecentTransactionRepository;
use StoreAuth\Tests\KeypairTrait;

#[CoversClass(className: MostRecentTransactionRepository::class)]
final class MostRecentTransactionRepositoryTest extends TestCase
{
    use KeypairTrait;

    public function testMostRecentTransaction(): void
    {
        // Setup bearer token.
        $bearerToken = "Z1TfjnIzC2WwCX7Es4dTuMvM6LusPVnj";
        $appleAccount = $this->createMock(ServiceAccount::class);
        $appleAccount->expects($this->once())
            ->method('getBearerToken')
            ->willReturn($bearerToken);

        // Setup request and request factory.
        $request = $this->createMock(RequestInterface::class);
        $request->expects($this->once())
            ->method("withHeader")
            ->with("Authorization", "Bearer $bearerToken")
            ->willReturn($request);

        $productId = "com.example.product-1";
        $transactionId = "161133706327570";

        $requestFactory = $this->createMock(RequestFactoryInterface::class);
        $requestFactory->expects($this->once())
            ->method("createRequest")
            ->with("GET", "https://api.storekit.itunes.apple.com/inApps/v2/history/$transactionId?productId=$productId&revoked=false&sort=DESCENDING")
            ->willReturn($request);

        // Setup cryptographic keys.
        ["private" => $privateKey, "public" => $publicKey] = $this->generateKeypair(self::EC_KEYPAIR_PARAMS);
        $signingAlgo = new Sha256();
        $signingKey = InMemory::plainText($privateKey);
        $constraints = [new SignedWith($signingAlgo, InMemory::plainText($publicKey))];

        // Setup response body.
        $transactionRecord = [
            "transactionId" => "$transactionId",
            "originalTransactionId" => "$transactionId",
            "bundleId" => "com.example.app",
            "productId" => "$productId",
            "purchaseDate" => 1718279022000,
            "originalPurchaseDate" => 1718279022000,
            "quantity" => 1,
            "type" => "Non-Consumable",
            "inAppOwnershipType" => "PURCHASED",
            "signedDate" => 1718625523676,
            "environment" => "Production",
            "transactionReason" => "PURCHASE",
            "storefront" => "CHE",
            "storefrontId" => "999999",
            "price" => 7000,
            "currency" => "CHF",
        ];
        $builder = new Token\Builder(new JoseEncoder(), ChainedFormatter::withUnixTimestampDates());
        foreach ($transactionRecord as $name => $value) {
            $builder = $builder->withClaim($name, $value);
        }
        $signedTransaction = $builder->getToken($signingAlgo, $signingKey)->toString();
        $responseRecord = [
            "signedTransactions" => [$signedTransaction],
        ];
        $responseJson = json_encode($responseRecord);

        $responseBody = $this->createMock(StreamInterface::class);
        $responseBody->expects($this->once())
            ->method('getContents')
            ->willReturn($responseJson);

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

        $repository = new MostRecentTransactionRepository($httpClient, $requestFactory, $appleAccount, $constraints);
        $result = $repository->get($productId, $transactionId);
        $this->assertSame($transactionRecord, $result);
    }

    public function testEmptyResponse(): void
    {
        // Setup bearer token.
        $bearerToken = "Z1TfjnIzC2WwCX7Es4dTuMvM6LusPVnj";
        $appleAccount = $this->createMock(ServiceAccount::class);
        $appleAccount->expects($this->once())
            ->method('getBearerToken')
            ->willReturn($bearerToken);

        // Setup request and request factory.
        $request = $this->createMock(RequestInterface::class);
        $request->expects($this->once())
            ->method("withHeader")
            ->with("Authorization", "Bearer $bearerToken")
            ->willReturn($request);

        $productId = "com.example.product-1";
        $transactionId = "161133706327570";

        $requestFactory = $this->createMock(RequestFactoryInterface::class);
        $requestFactory->expects($this->once())
            ->method("createRequest")
            ->with("GET", "https://api.storekit.itunes.apple.com/inApps/v2/history/$transactionId?productId=$productId&revoked=false&sort=DESCENDING")
            ->willReturn($request);

        // Setup response body.
        $responseRecord = [
            "signedTransactions" => [],
        ];
        $responseJson = json_encode($responseRecord);

        $responseBody = $this->createMock(StreamInterface::class);
        $responseBody->expects($this->once())
            ->method('getContents')
            ->willReturn($responseJson);

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

        $repository = new MostRecentTransactionRepository($httpClient, $requestFactory, $appleAccount, []);
        $result = $repository->get($productId, $transactionId);

        $this->assertFalse($result);
    }

    public function testAuthenticationFailure(): void
    {
        // Setup bearer token.
        $bearerToken = "Z1TfjnIzC2WwCX7Es4dTuMvM6LusPVnj";
        $appleAccount = $this->createMock(ServiceAccount::class);
        $appleAccount->expects($this->once())
            ->method('getBearerToken')
            ->willReturn($bearerToken);

        // Setup request and request factory.
        $request = $this->createMock(RequestInterface::class);
        $request->expects($this->once())
            ->method("withHeader")
            ->with("Authorization", "Bearer $bearerToken")
            ->willReturn($request);

        $productId = "com.example.product-1";
        $transactionId = "161133706327570";

        $requestFactory = $this->createMock(RequestFactoryInterface::class);
        $requestFactory->expects($this->once())
            ->method("createRequest")
            ->with("GET", "https://api.storekit.itunes.apple.com/inApps/v2/history/$transactionId?productId=$productId&revoked=false&sort=DESCENDING")
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

        $repository = new MostRecentTransactionRepository($httpClient, $requestFactory, $appleAccount, []);

        $this->expectException(StoreAuthException::class);
        $this->expectExceptionMessage("Failed to fetch transaction history from apple storekit endpoint. Response status=401");
        $repository->get($productId, $transactionId);
    }

    public function testInvalidJsonResponse(): void
    {
        // Setup bearer token.
        $bearerToken = "Z1TfjnIzC2WwCX7Es4dTuMvM6LusPVnj";
        $appleAccount = $this->createMock(ServiceAccount::class);
        $appleAccount->expects($this->once())
            ->method('getBearerToken')
            ->willReturn($bearerToken);

        // Setup request and request factory.
        $request = $this->createMock(RequestInterface::class);
        $request->expects($this->once())
            ->method("withHeader")
            ->with("Authorization", "Bearer $bearerToken")
            ->willReturn($request);

        $productId = "com.example.product-1";
        $transactionId = "161133706327570";

        $requestFactory = $this->createMock(RequestFactoryInterface::class);
        $requestFactory->expects($this->once())
            ->method("createRequest")
            ->with("GET", "https://api.storekit.itunes.apple.com/inApps/v2/history/$transactionId?productId=$productId&revoked=false&sort=DESCENDING")
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

        $repository = new MostRecentTransactionRepository($httpClient, $requestFactory, $appleAccount, []);

        $this->expectException(StoreAuthException::class);
        $this->expectExceptionMessage("Failed to parse data returned from apple storekit transaction history endpoint.");
        $repository->get($productId, $transactionId);
    }

    public function testSignatureFailure(): void
    {
        // Setup bearer token.
        $bearerToken = "Z1TfjnIzC2WwCX7Es4dTuMvM6LusPVnj";
        $appleAccount = $this->createMock(ServiceAccount::class);
        $appleAccount->expects($this->once())
            ->method('getBearerToken')
            ->willReturn($bearerToken);

        // Setup request and request factory.
        $request = $this->createMock(RequestInterface::class);
        $request->expects($this->once())
            ->method("withHeader")
            ->with("Authorization", "Bearer $bearerToken")
            ->willReturn($request);

        $productId = "com.example.product-1";
        $transactionId = "161133706327570";

        $requestFactory = $this->createMock(RequestFactoryInterface::class);
        $requestFactory->expects($this->once())
            ->method("createRequest")
            ->with("GET", "https://api.storekit.itunes.apple.com/inApps/v2/history/$transactionId?productId=$productId&revoked=false&sort=DESCENDING")
            ->willReturn($request);

        // Setup cryptographic keys.
        ["private" => $privateKey] = $this->generateKeypair(self::EC_KEYPAIR_PARAMS);
        $signingAlgo = new Sha256();
        $signingKey = InMemory::plainText($privateKey);

        // Setup response body.
        $transactionRecord = [
            "transactionId" => "$transactionId",
            "originalTransactionId" => "$transactionId",
            "bundleId" => "com.example.app",
            "productId" => "$productId",
            "purchaseDate" => 1718279022000,
            "originalPurchaseDate" => 1718279022000,
            "quantity" => 1,
            "type" => "Non-Consumable",
            "inAppOwnershipType" => "PURCHASED",
            "signedDate" => 1718625523676,
            "environment" => "Production",
            "transactionReason" => "PURCHASE",
            "storefront" => "CHE",
            "storefrontId" => "999999",
            "price" => 7000,
            "currency" => "CHF",
        ];
        $builder = new Token\Builder(new JoseEncoder(), ChainedFormatter::withUnixTimestampDates());
        foreach ($transactionRecord as $name => $value) {
            $builder = $builder->withClaim($name, $value);
        }
        $signedTransaction = $builder->getToken($signingAlgo, $signingKey)->toString();
        $responseRecord = [
            "signedTransactions" => [$signedTransaction],
        ];
        $responseJson = json_encode($responseRecord);

        $responseBody = $this->createMock(StreamInterface::class);
        $responseBody->expects($this->once())
            ->method('getContents')
            ->willReturn($responseJson);

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

        ["public" => $unrelatedPublicKey] = $this->generateKeypair(self::EC_KEYPAIR_PARAMS);
        $constraints = [new SignedWith($signingAlgo, InMemory::plainText($unrelatedPublicKey))];

        $repository = new MostRecentTransactionRepository($httpClient, $requestFactory, $appleAccount, $constraints);

        $this->expectException(StoreAuthException::class);
        $this->expectExceptionMessage("Verification failed for data returned from apple storekit transaction history endpoint.");
        $repository->get($productId, $transactionId);
    }
}
