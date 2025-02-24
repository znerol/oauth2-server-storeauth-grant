<?php

declare(strict_types=1);

namespace StoreAuth\Tests\Oauth2\Server\Grant;

use DateInterval;
use DG\BypassFinals;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\EventEmitting\EventEmitter;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestAccessTokenEvent;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use StoreAuth\Exceptions\StoreAuthException;
use StoreAuth\Oauth2\Server\Entities\NonConsumableEntityInterface;
use StoreAuth\Oauth2\Server\Grant\AppleNonConsumable;
use StoreAuth\Oauth2\Server\Repositories\NonConsumableRepositoryInterface;
use StoreAuth\Oauth2\Server\StoreFactories\AppleMostRecentTransactionFactoryInterface;
use StoreAuth\Stores\Apple\MostRecentTransactionRepository;
use StoreAuth\Tests\KeypairTrait;
use StoreAuth\Tests\PHPUnit\ClosureMock;

#[CoversClass(className: AppleNonConsumable::class)]
final class AppleNonConsumableTest extends TestCase
{
    use KeypairTrait;

    private const DEFAULT_SCOPE = "basic";

    public static function setUpBeforeClass(): void
    {
        BypassFinals::setWhitelist(["*/Stores/Apple/MostRecentTransactionRepository.php"]);
        BypassFinals::enable();
    }

    public function testRespondToRequest(): void
    {
        $clientId = "test-client-72b86b49";
        $scope = "product-1";
        $sku = "com.example.product-1";
        $transactionId = "161133706327570";

        $clientEntity = $this->createStub(ClientEntityInterface::class);
        $clientRepository = $this->createMock(ClientRepositoryInterface::class);
        $clientRepository->expects($this->once())
            ->method("getClientEntity")
            ->with($clientId)
            ->willReturn($clientEntity);

        $scopeEntity = $this->createStub(ScopeEntityInterface::class);
        $scopeRepository = $this->createMock(ScopeRepositoryInterface::class);
        $scopeRepository->expects($this->once())
            ->method("getScopeEntityByIdentifier")
            ->with($scope)
            ->willReturn($scopeEntity);
        $scopeRepository->expects($this->once())
            ->method("finalizeScopes")
            ->with([$scopeEntity], "urn:uuid:c7e545a5-d72b-4294-a173-bb1858aae099", $clientEntity)
            ->willReturn([$scopeEntity]);

        $accessTokenEntity = $this->createStub(AccessTokenEntityInterface::class);
        $accessTokenRepository = $this->createMock(AccessTokenRepositoryInterface::class);
        $accessTokenRepository->expects($this->once())
            ->method("getNewToken")
            ->with($clientEntity, [$scopeEntity])
            ->willReturn($accessTokenEntity);
        $accessTokenRepository->expects($this->once())
            ->method("persistNewAccessToken")
            ->with($accessTokenEntity);

        $product = $this->createMock(NonConsumableEntityInterface::class);
        $product->expects($this->once())
            ->method("getSku")
            ->willReturn($sku);

        $productRepository = $this->createMock(NonConsumableRepositoryInterface::class);
        $productRepository->expects($this->once())
            ->method("getNonConsumableFromScope")
            ->with([$scopeEntity])
            ->willReturn($product);

        // @phpstan-ignore method.unresolvableReturnType
        $purchaseRepository = $this->createMock(MostRecentTransactionRepository::class);
        $purchaseRepository->expects($this->once())
            ->method("get")
            ->with($sku, $transactionId)
            ->willReturn([
                "type" => "Non-Consumable",
            ]);

        $serviceFactory = $this->createMock(AppleMostRecentTransactionFactoryInterface::class);
        $serviceFactory->expects($this->once())
            ->method("getRepositoryForClient")
            ->with($clientEntity)
            ->willReturn($purchaseRepository);

        $listener = $this->createMock(ClosureMock::class);
        assert(is_callable($listener));
        $listener->expects($this->once())
            ->method('__invoke')
            ->with($this->isInstanceOf(RequestAccessTokenEvent::class));
        $eventEmitter = new EventEmitter();
        $eventEmitter->addListener(RequestEvent::ACCESS_TOKEN_ISSUED, $listener);

        ["private" => $privateKey] = $this->generateKeypair(self::RSA_KEYPAIR_PARAMS);

        $grant = new AppleNonConsumable($productRepository, $serviceFactory);
        $grant->setClientRepository($clientRepository);
        $grant->setAccessTokenRepository($accessTokenRepository);
        $grant->setScopeRepository($scopeRepository);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setPrivateKey(new CryptKey($privateKey));
        $grant->setEmitter($eventEmitter);

        $serverRequest = (new ServerRequest())->withParsedBody([
            "client_id"         => $clientId,
            "transaction_id"    => $transactionId,
            "scope"             => $scope,
        ]);

        $responseType = $this->createMock(ResponseTypeInterface::class);
        $responseType->expects($this->once())
            ->method("setAccessToken")
            ->with($accessTokenEntity);

        $response = $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval("PT5M"));
        $this->assertSame($responseType, $response);
    }

    public function testClientIdMissing(): void
    {
        $scope = "product-1";
        $transactionId = "161133706327570";

        $clientRepository = $this->createStub(ClientRepositoryInterface::class);
        $scopeRepository = $this->createStub(ScopeRepositoryInterface::class);
        $accessTokenRepository = $this->createStub(AccessTokenRepositoryInterface::class);
        $productRepository = $this->createStub(NonConsumableRepositoryInterface::class);
        $serviceFactory = $this->createStub(AppleMostRecentTransactionFactoryInterface::class);
        $eventEmitter = new EventEmitter();

        ["private" => $privateKey] = $this->generateKeypair(self::RSA_KEYPAIR_PARAMS);

        $grant = new AppleNonConsumable($productRepository, $serviceFactory);
        $grant->setClientRepository($clientRepository);
        $grant->setAccessTokenRepository($accessTokenRepository);
        $grant->setScopeRepository($scopeRepository);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setPrivateKey(new CryptKey($privateKey));
        $grant->setEmitter($eventEmitter);

        $serverRequest = (new ServerRequest())->withParsedBody([
            "transaction_id"    => $transactionId,
            "scope"             => $scope,
        ]);

        $responseType = $this->createStub(ResponseTypeInterface::class);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionMessage("The request is missing a required parameter");
        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval("PT5M"));
    }

    public function testClientIdLookupFailure(): void
    {
        $clientId = "test-client-72b86b49";
        $scope = "product-1";
        $transactionId = "161133706327570";

        $clientRepository = $this->createMock(ClientRepositoryInterface::class);
        $clientRepository->expects($this->once())
            ->method("getClientEntity")
            ->with($clientId)
            ->willReturn(null);

        $scopeRepository = $this->createStub(ScopeRepositoryInterface::class);
        $accessTokenRepository = $this->createStub(AccessTokenRepositoryInterface::class);
        $productRepository = $this->createStub(NonConsumableRepositoryInterface::class);
        $serviceFactory = $this->createStub(AppleMostRecentTransactionFactoryInterface::class);
        $listener = $this->createMock(ClosureMock::class);
        assert(is_callable($listener));
        $listener->expects($this->once())
            ->method('__invoke')
            ->with($this->isInstanceOf(RequestEvent::class));
        $eventEmitter = new EventEmitter();
        $eventEmitter->addListener(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $listener);

        ["private" => $privateKey] = $this->generateKeypair(self::RSA_KEYPAIR_PARAMS);

        $grant = new AppleNonConsumable($productRepository, $serviceFactory);
        $grant->setClientRepository($clientRepository);
        $grant->setAccessTokenRepository($accessTokenRepository);
        $grant->setScopeRepository($scopeRepository);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setPrivateKey(new CryptKey($privateKey));
        $grant->setEmitter($eventEmitter);

        $serverRequest = (new ServerRequest())->withParsedBody([
            "client_id"         => $clientId,
            "transaction_id"    => $transactionId,
            "scope"             => $scope,
        ]);

        $responseType = $this->createStub(ResponseTypeInterface::class);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionMessage("Client authentication failed");
        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval("PT5M"));
    }

    public function testServiceMissing(): void
    {
        $clientId = "test-client-72b86b49";
        $scope = "product-1";
        $transactionId = "161133706327570";

        $clientEntity = $this->createStub(ClientEntityInterface::class);
        $clientRepository = $this->createMock(ClientRepositoryInterface::class);
        $clientRepository->expects($this->once())
            ->method("getClientEntity")
            ->with($clientId)
            ->willReturn($clientEntity);

        $scopeRepository = $this->createStub(ScopeRepositoryInterface::class);
        $accessTokenRepository = $this->createStub(AccessTokenRepositoryInterface::class);
        $productRepository = $this->createStub(NonConsumableRepositoryInterface::class);

        $serviceFactory = $this->createMock(AppleMostRecentTransactionFactoryInterface::class);
        $serviceFactory->expects($this->once())
            ->method("getRepositoryForClient")
            ->with($clientEntity)
            ->willReturn(null);

        $eventEmitter = new EventEmitter();

        ["private" => $privateKey] = $this->generateKeypair(self::RSA_KEYPAIR_PARAMS);

        $grant = new AppleNonConsumable($productRepository, $serviceFactory);
        $grant->setClientRepository($clientRepository);
        $grant->setAccessTokenRepository($accessTokenRepository);
        $grant->setScopeRepository($scopeRepository);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setPrivateKey(new CryptKey($privateKey));
        $grant->setEmitter($eventEmitter);

        $serverRequest = (new ServerRequest())->withParsedBody([
            "client_id"         => $clientId,
            "transaction_id"    => $transactionId,
            "scope"             => $scope,
        ]);

        $responseType = $this->createStub(ResponseTypeInterface::class);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionMessage("The request is missing a required parameter, includes an invalid parameter value");
        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval("PT5M"));
    }

    public function testScopeInvalid(): void
    {
        $clientId = "test-client-72b86b49";
        $scope = "product-1";
        $transactionId = "161133706327570";

        $clientEntity = $this->createStub(ClientEntityInterface::class);
        $clientRepository = $this->createMock(ClientRepositoryInterface::class);
        $clientRepository->expects($this->once())
            ->method("getClientEntity")
            ->with($clientId)
            ->willReturn($clientEntity);

        $scopeRepository = $this->createMock(ScopeRepositoryInterface::class);
        $scopeRepository->expects($this->once())
            ->method("getScopeEntityByIdentifier")
            ->with($scope)
            ->willReturn(null);

        $accessTokenRepository = $this->createStub(AccessTokenRepositoryInterface::class);
        $productRepository = $this->createStub(NonConsumableRepositoryInterface::class);

        // @phpstan-ignore method.unresolvableReturnType
        $purchaseRepository = $this->createStub(MostRecentTransactionRepository::class);

        $serviceFactory = $this->createMock(AppleMostRecentTransactionFactoryInterface::class);
        $serviceFactory->expects($this->once())
            ->method("getRepositoryForClient")
            ->with($clientEntity)
            ->willReturn($purchaseRepository);

        $eventEmitter = new EventEmitter();

        ["private" => $privateKey] = $this->generateKeypair(self::RSA_KEYPAIR_PARAMS);

        $grant = new AppleNonConsumable($productRepository, $serviceFactory);
        $grant->setClientRepository($clientRepository);
        $grant->setAccessTokenRepository($accessTokenRepository);
        $grant->setScopeRepository($scopeRepository);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setPrivateKey(new CryptKey($privateKey));
        $grant->setEmitter($eventEmitter);

        $serverRequest = (new ServerRequest())->withParsedBody([
            "client_id"         => $clientId,
            "transaction_id"    => $transactionId,
            "scope"             => $scope,
        ]);

        $responseType = $this->createStub(ResponseTypeInterface::class);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionMessage("The requested scope is invalid, unknown, or malformed");
        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval("PT5M"));
    }

    public function testProductInvalid(): void
    {
        $clientId = "test-client-72b86b49";
        $scope = "product-1";
        $transactionId = "161133706327570";

        $clientEntity = $this->createStub(ClientEntityInterface::class);
        $clientRepository = $this->createMock(ClientRepositoryInterface::class);
        $clientRepository->expects($this->once())
            ->method("getClientEntity")
            ->with($clientId)
            ->willReturn($clientEntity);

        $scopeEntity = $this->createStub(ScopeEntityInterface::class);
        $scopeRepository = $this->createMock(ScopeRepositoryInterface::class);
        $scopeRepository->expects($this->once())
            ->method("getScopeEntityByIdentifier")
            ->with($scope)
            ->willReturn($scopeEntity);
        $scopeRepository->expects($this->once())
            ->method("finalizeScopes")
            ->with([$scopeEntity], "urn:uuid:c7e545a5-d72b-4294-a173-bb1858aae099", $clientEntity)
            ->willReturn([$scopeEntity]);

        $accessTokenRepository = $this->createStub(AccessTokenRepositoryInterface::class);

        $productRepository = $this->createMock(NonConsumableRepositoryInterface::class);
        $productRepository->expects($this->once())
            ->method("getNonConsumableFromScope")
            ->with([$scopeEntity])
            ->willReturn(null);

        // @phpstan-ignore method.unresolvableReturnType
        $purchaseRepository = $this->createStub(MostRecentTransactionRepository::class);

        $serviceFactory = $this->createMock(AppleMostRecentTransactionFactoryInterface::class);
        $serviceFactory->expects($this->once())
            ->method("getRepositoryForClient")
            ->with($clientEntity)
            ->willReturn($purchaseRepository);

        $eventEmitter = new EventEmitter();

        ["private" => $privateKey] = $this->generateKeypair(self::RSA_KEYPAIR_PARAMS);

        $grant = new AppleNonConsumable($productRepository, $serviceFactory);
        $grant->setClientRepository($clientRepository);
        $grant->setAccessTokenRepository($accessTokenRepository);
        $grant->setScopeRepository($scopeRepository);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setPrivateKey(new CryptKey($privateKey));
        $grant->setEmitter($eventEmitter);

        $serverRequest = (new ServerRequest())->withParsedBody([
            "client_id"         => $clientId,
            "transaction_id"    => $transactionId,
            "scope"             => $scope,
        ]);

        $responseType = $this->createStub(ResponseTypeInterface::class);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionMessage("The requested scope is invalid, unknown, or malformed");
        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval("PT5M"));
    }

    public function testTransactionIdMissing(): void
    {
        $clientId = "test-client-72b86b49";
        $scope = "product-1";

        $clientEntity = $this->createStub(ClientEntityInterface::class);
        $clientRepository = $this->createMock(ClientRepositoryInterface::class);
        $clientRepository->expects($this->once())
            ->method("getClientEntity")
            ->with($clientId)
            ->willReturn($clientEntity);

        $scopeEntity = $this->createStub(ScopeEntityInterface::class);
        $scopeRepository = $this->createMock(ScopeRepositoryInterface::class);
        $scopeRepository->expects($this->once())
            ->method("getScopeEntityByIdentifier")
            ->with($scope)
            ->willReturn($scopeEntity);
        $scopeRepository->expects($this->once())
            ->method("finalizeScopes")
            ->with([$scopeEntity], "urn:uuid:c7e545a5-d72b-4294-a173-bb1858aae099", $clientEntity)
            ->willReturn([$scopeEntity]);

        $accessTokenRepository = $this->createStub(AccessTokenRepositoryInterface::class);

        $product = $this->createStub(NonConsumableEntityInterface::class);
        $productRepository = $this->createMock(NonConsumableRepositoryInterface::class);
        $productRepository->expects($this->once())
            ->method("getNonConsumableFromScope")
            ->with([$scopeEntity])
            ->willReturn($product);

        // @phpstan-ignore method.unresolvableReturnType
        $purchaseRepository = $this->createStub(MostRecentTransactionRepository::class);

        $serviceFactory = $this->createMock(AppleMostRecentTransactionFactoryInterface::class);
        $serviceFactory->expects($this->once())
            ->method("getRepositoryForClient")
            ->with($clientEntity)
            ->willReturn($purchaseRepository);

        $eventEmitter = new EventEmitter();

        ["private" => $privateKey] = $this->generateKeypair(self::RSA_KEYPAIR_PARAMS);

        $grant = new AppleNonConsumable($productRepository, $serviceFactory);
        $grant->setClientRepository($clientRepository);
        $grant->setAccessTokenRepository($accessTokenRepository);
        $grant->setScopeRepository($scopeRepository);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setPrivateKey(new CryptKey($privateKey));
        $grant->setEmitter($eventEmitter);

        $serverRequest = (new ServerRequest())->withParsedBody([
            "client_id"         => $clientId,
            "scope"             => $scope,
        ]);

        $responseType = $this->createStub(ResponseTypeInterface::class);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionMessage("The request is missing a required parameter");
        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval("PT5M"));
    }

    public function testPurchaseLookupFailure(): void
    {
        $clientId = "test-client-72b86b49";
        $scope = "product-1";
        $sku = "com.example.product-1";
        $transactionId = "161133706327570";

        $clientEntity = $this->createStub(ClientEntityInterface::class);
        $clientRepository = $this->createMock(ClientRepositoryInterface::class);
        $clientRepository->expects($this->once())
            ->method("getClientEntity")
            ->with($clientId)
            ->willReturn($clientEntity);

        $scopeEntity = $this->createStub(ScopeEntityInterface::class);
        $scopeRepository = $this->createMock(ScopeRepositoryInterface::class);
        $scopeRepository->expects($this->once())
            ->method("getScopeEntityByIdentifier")
            ->with($scope)
            ->willReturn($scopeEntity);
        $scopeRepository->expects($this->once())
            ->method("finalizeScopes")
            ->with([$scopeEntity], "urn:uuid:c7e545a5-d72b-4294-a173-bb1858aae099", $clientEntity)
            ->willReturn([$scopeEntity]);

        $accessTokenRepository = $this->createStub(AccessTokenRepositoryInterface::class);

        $product = $this->createMock(NonConsumableEntityInterface::class);
        $product->expects($this->once())
            ->method("getSku")
            ->willReturn($sku);

        $productRepository = $this->createMock(NonConsumableRepositoryInterface::class);
        $productRepository->expects($this->once())
            ->method("getNonConsumableFromScope")
            ->with([$scopeEntity])
            ->willReturn($product);

        // @phpstan-ignore method.unresolvableReturnType
        $purchaseRepository = $this->createMock(MostRecentTransactionRepository::class);
        $purchaseRepository->expects($this->once())
            ->method("get")
            ->willThrowException(new StoreAuthException("Failed to fetch transaction history from apple storekit endpoint. Response status=401"));

        $serviceFactory = $this->createMock(AppleMostRecentTransactionFactoryInterface::class);
        $serviceFactory->expects($this->once())
            ->method("getRepositoryForClient")
            ->with($clientEntity)
            ->willReturn($purchaseRepository);

        $eventEmitter = new EventEmitter();

        ["private" => $privateKey] = $this->generateKeypair(self::RSA_KEYPAIR_PARAMS);

        $grant = new AppleNonConsumable($productRepository, $serviceFactory);
        $grant->setClientRepository($clientRepository);
        $grant->setAccessTokenRepository($accessTokenRepository);
        $grant->setScopeRepository($scopeRepository);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setPrivateKey(new CryptKey($privateKey));
        $grant->setEmitter($eventEmitter);

        $serverRequest = (new ServerRequest())->withParsedBody([
            "client_id"         => $clientId,
            "transaction_id"    => $transactionId,
            "scope"             => $scope,
        ]);

        $responseType = $this->createStub(ResponseTypeInterface::class);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionMessage("The authorization server encountered an unexpected condition which prevented it from fulfilling the request: Failed to retrieve product purchase status");
        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval("PT5M"));
    }

    public function testPurchaseLookupNoResult(): void
    {
        $clientId = "test-client-72b86b49";
        $scope = "product-1";
        $sku = "com.example.product-1";
        $transactionId = "161133706327570";

        $clientEntity = $this->createStub(ClientEntityInterface::class);
        $clientRepository = $this->createMock(ClientRepositoryInterface::class);
        $clientRepository->expects($this->once())
            ->method("getClientEntity")
            ->with($clientId)
            ->willReturn($clientEntity);

        $scopeEntity = $this->createStub(ScopeEntityInterface::class);
        $scopeRepository = $this->createMock(ScopeRepositoryInterface::class);
        $scopeRepository->expects($this->once())
            ->method("getScopeEntityByIdentifier")
            ->with($scope)
            ->willReturn($scopeEntity);
        $scopeRepository->expects($this->once())
            ->method("finalizeScopes")
            ->with([$scopeEntity], "urn:uuid:c7e545a5-d72b-4294-a173-bb1858aae099", $clientEntity)
            ->willReturn([$scopeEntity]);

        $accessTokenRepository = $this->createStub(AccessTokenRepositoryInterface::class);

        $product = $this->createMock(NonConsumableEntityInterface::class);
        $product->expects($this->once())
            ->method("getSku")
            ->willReturn($sku);

        $productRepository = $this->createMock(NonConsumableRepositoryInterface::class);
        $productRepository->expects($this->once())
            ->method("getNonConsumableFromScope")
            ->with([$scopeEntity])
            ->willReturn($product);

        // @phpstan-ignore method.unresolvableReturnType
        $purchaseRepository = $this->createMock(MostRecentTransactionRepository::class);
        $purchaseRepository->expects($this->once())
            ->method("get")
            ->with($sku, $transactionId)
            ->willReturn(false);

        $serviceFactory = $this->createMock(AppleMostRecentTransactionFactoryInterface::class);
        $serviceFactory->expects($this->once())
            ->method("getRepositoryForClient")
            ->with($clientEntity)
            ->willReturn($purchaseRepository);

        $eventEmitter = new EventEmitter();

        ["private" => $privateKey] = $this->generateKeypair(self::RSA_KEYPAIR_PARAMS);

        $grant = new AppleNonConsumable($productRepository, $serviceFactory);
        $grant->setClientRepository($clientRepository);
        $grant->setAccessTokenRepository($accessTokenRepository);
        $grant->setScopeRepository($scopeRepository);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setPrivateKey(new CryptKey($privateKey));
        $grant->setEmitter($eventEmitter);

        $serverRequest = (new ServerRequest())->withParsedBody([
            "client_id"         => $clientId,
            "transaction_id"    => $transactionId,
            "scope"             => $scope,
        ]);

        $responseType = $this->createStub(ResponseTypeInterface::class);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionMessage("The user credentials were incorrect.");
        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval("PT5M"));
    }
}
