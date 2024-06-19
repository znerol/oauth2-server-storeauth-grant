<?php

declare(strict_types=1);

namespace StoreAuth\Tests\Stores\Google;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use StoreAuth\Exceptions\StoreAuthException;
use StoreAuth\Oauth2\ServiceAccount;
use StoreAuth\Stores\Google\ProductPurchaseRepository;
use StoreAuth\Tests\KeypairTrait;

#[CoversClass(className: ProductPurchaseRepository::class)]
final class ProductPurchaseRepositoryTest extends TestCase
{
    use KeypairTrait;

    public function testProductPurchase(): void
    {
        // Setup bearer token.
        $bearerToken = "Z1TfjnIzC2WwCX7Es4dTuMvM6LusPVnj";
        $googleAccount = $this->createMock(ServiceAccount::class);
        $googleAccount->expects($this->once())
            ->method('getBearerToken')
            ->willReturn($bearerToken);

        // Setup request and request factory.
        $request = $this->createMock(RequestInterface::class);
        $request->expects($this->once())
            ->method("withHeader")
            ->with("Authorization", "Bearer $bearerToken")
            ->willReturn($request);

        $packageId = 'com.example.app';
        $productId = "com.example.product-1";
        $purchaseToken = "IJirr23bCwjk6z8H9URO0CRC9xNHGB9Z";

        $requestFactory = $this->createMock(RequestFactoryInterface::class);
        $requestFactory->expects($this->once())
            ->method("createRequest")
            ->with("GET", "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/$packageId/purchases/products/$productId/tokens/$purchaseToken")
            ->willReturn($request);

        // Setup response body.
        $transactionRecord = [
            "acknowledgementState" => 1,
            "consumptionState" => 0,
            "developerPayload" => "",
            "kind" => "androidpublisher#productPurchase",
            "orderId" => "GPA.9999-9999-9999-99999",
            "purchaseState" => 0,
            "purchaseTimeMillis" => "1707206281438",
            "purchaseType" => 0,
            "regionCode" => "CH",
        ];
        $responseJson = json_encode($transactionRecord);

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

        $repository = new ProductPurchaseRepository($packageId, $httpClient, $requestFactory, $googleAccount);
        $result = $repository->get($productId, $purchaseToken);
        $this->assertSame($transactionRecord, $result);
    }

    public function testAuthenticationFailure(): void
    {
        // Setup bearer token.
        $bearerToken = "Z1TfjnIzC2WwCX7Es4dTuMvM6LusPVnj";
        $googleAccount = $this->createMock(ServiceAccount::class);
        $googleAccount->expects($this->once())
            ->method('getBearerToken')
            ->willReturn($bearerToken);

        // Setup request and request factory.
        $request = $this->createMock(RequestInterface::class);
        $request->expects($this->once())
            ->method("withHeader")
            ->with("Authorization", "Bearer $bearerToken")
            ->willReturn($request);

        $packageId = 'com.example.app';
        $productId = "com.example.product-1";
        $purchaseToken = "IJirr23bCwjk6z8H9URO0CRC9xNHGB9Z";

        $requestFactory = $this->createMock(RequestFactoryInterface::class);
        $requestFactory->expects($this->once())
            ->method("createRequest")
            ->with("GET", "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/$packageId/purchases/products/$productId/tokens/$purchaseToken")
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

        $repository = new ProductPurchaseRepository($packageId, $httpClient, $requestFactory, $googleAccount);

        $this->expectException(StoreAuthException::class);
        $this->expectExceptionMessage("Failed to fetch product purchase from google endpoint. Response status=401");
        $repository->get($productId, $purchaseToken);
    }

    public function testInvalidResponse(): void
    {
        // Setup bearer token.
        $bearerToken = "Z1TfjnIzC2WwCX7Es4dTuMvM6LusPVnj";
        $googleAccount = $this->createMock(ServiceAccount::class);
        $googleAccount->expects($this->once())
            ->method('getBearerToken')
            ->willReturn($bearerToken);

        // Setup request and request factory.
        $request = $this->createMock(RequestInterface::class);
        $request->expects($this->once())
            ->method("withHeader")
            ->with("Authorization", "Bearer $bearerToken")
            ->willReturn($request);

        $packageId = 'com.example.app';
        $productId = "com.example.product-1";
        $purchaseToken = "IJirr23bCwjk6z8H9URO0CRC9xNHGB9Z";

        $requestFactory = $this->createMock(RequestFactoryInterface::class);
        $requestFactory->expects($this->once())
            ->method("createRequest")
            ->with("GET", "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/$packageId/purchases/products/$productId/tokens/$purchaseToken")
            ->willReturn($request);

        // Setup response.
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

        $repository = new ProductPurchaseRepository($packageId, $httpClient, $requestFactory, $googleAccount);

        $this->expectException(StoreAuthException::class);
        $this->expectExceptionMessage("Unexpected data returned from google product purchase endpoint.");
        $repository->get($productId, $purchaseToken);
    }

    public function testProductAcknowledgement(): void
    {
        // Setup bearer token.
        $bearerToken = "Z1TfjnIzC2WwCX7Es4dTuMvM6LusPVnj";
        $googleAccount = $this->createMock(ServiceAccount::class);
        $googleAccount->expects($this->once())
            ->method('getBearerToken')
            ->willReturn($bearerToken);

        // Setup request and request factory.
        $request = $this->createMock(RequestInterface::class);
        $request->expects($this->once())
            ->method("withHeader")
            ->with("Authorization", "Bearer $bearerToken")
            ->willReturn($request);

        $packageId = 'com.example.app';
        $productId = "com.example.product-1";
        $purchaseToken = "IJirr23bCwjk6z8H9URO0CRC9xNHGB9Z";

        $requestFactory = $this->createMock(RequestFactoryInterface::class);
        $requestFactory->expects($this->once())
            ->method("createRequest")
            ->with("POST", "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/$packageId/purchases/products/$productId/tokens/$purchaseToken:acknowledge")
            ->willReturn($request);

        // Setup response.
        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->once())
            ->method('getStatusCode')
            ->willReturn(200);

        // Setup HTTP client.
        $httpClient = $this->createMock(ClientInterface::class);
        $httpClient->expects($this->once())
            ->method('sendRequest')
            ->with($request)
            ->willReturn($response);

        $repository = new ProductPurchaseRepository($packageId, $httpClient, $requestFactory, $googleAccount);
        $repository->acknowledge($productId, $purchaseToken);
    }


    public function testAcknowledgementAuthenticationFailure(): void
    {
        // Setup bearer token.
        $bearerToken = "Z1TfjnIzC2WwCX7Es4dTuMvM6LusPVnj";
        $googleAccount = $this->createMock(ServiceAccount::class);
        $googleAccount->expects($this->once())
            ->method('getBearerToken')
            ->willReturn($bearerToken);

        // Setup request and request factory.
        $request = $this->createMock(RequestInterface::class);
        $request->expects($this->once())
            ->method("withHeader")
            ->with("Authorization", "Bearer $bearerToken")
            ->willReturn($request);

        $packageId = 'com.example.app';
        $productId = "com.example.product-1";
        $purchaseToken = "IJirr23bCwjk6z8H9URO0CRC9xNHGB9Z";

        $requestFactory = $this->createMock(RequestFactoryInterface::class);
        $requestFactory->expects($this->once())
            ->method("createRequest")
            ->with("POST", "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/$packageId/purchases/products/$productId/tokens/$purchaseToken:acknowledge")
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

        $repository = new ProductPurchaseRepository($packageId, $httpClient, $requestFactory, $googleAccount);

        $this->expectException(StoreAuthException::class);
        $this->expectExceptionMessage("Failed to acknowledge product purchase at google endpoint. Response status=401");
        $repository->acknowledge($productId, $purchaseToken);
    }
}
