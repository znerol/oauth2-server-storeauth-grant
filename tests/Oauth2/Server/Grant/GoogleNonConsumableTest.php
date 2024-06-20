<?php

declare(strict_types=1);

namespace StoreAuth\Tests\Oauth2\Server\Grant;

use DateInterval;
use DG\BypassFinals;
use Laminas\Diactoros\ServerRequest;
use League\Event\EmitterInterface;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
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
use StoreAuth\Oauth2\Server\Grant\GoogleNonConsumable;
use StoreAuth\Oauth2\Server\Repositories\NonConsumableRepositoryInterface;
use StoreAuth\Oauth2\Server\StoreFactories\GoogleProductPurchaseFactoryInterface;
use StoreAuth\Stores\Google\ProductPurchaseRepository;
use StoreAuth\Tests\KeypairTrait;

#[CoversClass(className: GoogleNonConsumable::class)]
final class GoogleNonConsumableTest extends TestCase
{
    use KeypairTrait;

    private const DEFAULT_SCOPE = "basic";

    public static function setUpBeforeClass(): void
    {
        BypassFinals::setWhitelist(["*/Stores/Google/ProductPurchaseRepository.php"]);
        BypassFinals::enable();
    }

    public function testRespondToRequest(): void
    {
        $clientId = "test-client-72b86b49";
        $scope = "product-1";
        $sku = "com.example.product-1";
        $purchaseToken = "IJirr23bCwjk6z8H9URO0CRC9xNHGB9Z";

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
            ->with([$scopeEntity], "urn:uuid:ea31e77f-cb72-486f-b5c4-deef43e839f3", $clientEntity)
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
        $purchaseRepository = $this->createMock(ProductPurchaseRepository::class);
        $purchaseRepository->expects($this->once())
            ->method("get")
            ->with($sku, $purchaseToken)
            ->willReturn([
                "acknowledgementState" => 1,
                "purchaseState" => 0,
            ]);

        $serviceFactory = $this->createMock(GoogleProductPurchaseFactoryInterface::class);
        $serviceFactory->expects($this->once())
            ->method("getRepositoryForClient")
            ->with($clientEntity)
            ->willReturn($purchaseRepository);

        $eventEmitter = $this->createMock(EmitterInterface::class);
        $eventEmitter->expects($this->once())
            ->method("emit")
            ->with($this->isInstanceOf(RequestAccessTokenEvent::class));

        ["private" => $privateKey] = $this->generateKeypair(self::RSA_KEYPAIR_PARAMS);

        $grant = new GoogleNonConsumable($productRepository, $serviceFactory);
        $grant->setClientRepository($clientRepository);
        $grant->setAccessTokenRepository($accessTokenRepository);
        $grant->setScopeRepository($scopeRepository);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setPrivateKey(new CryptKey($privateKey));
        $grant->setEmitter($eventEmitter);

        $serverRequest = (new ServerRequest())->withParsedBody([
            "client_id"         => $clientId,
            "purchase_token"    => $purchaseToken,
            "scope"             => $scope,
        ]);

        $responseType = $this->createMock(ResponseTypeInterface::class);
        $responseType->expects($this->once())
            ->method("setAccessToken")
            ->with($accessTokenEntity);

        $response = $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval("PT5M"));
        $this->assertSame($responseType, $response);
    }

    public function testRespondToRequestAndAcknowledge(): void
    {
        $clientId = "test-client-72b86b49";
        $scope = "product-1";
        $sku = "com.example.product-1";
        $purchaseToken = "IJirr23bCwjk6z8H9URO0CRC9xNHGB9Z";

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
            ->with([$scopeEntity], "urn:uuid:ea31e77f-cb72-486f-b5c4-deef43e839f3", $clientEntity)
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
        $purchaseRepository = $this->createMock(ProductPurchaseRepository::class);
        $purchaseRepository->expects($this->once())
            ->method("get")
            ->with($sku, $purchaseToken)
            ->willReturn([
                "acknowledgementState" => 0,
                "purchaseState" => 0,
            ]);
        $purchaseRepository->expects($this->once())
            ->method("acknowledge")
            ->with($sku, $purchaseToken);

        $serviceFactory = $this->createMock(GoogleProductPurchaseFactoryInterface::class);
        $serviceFactory->expects($this->once())
            ->method("getRepositoryForClient")
            ->with($clientEntity)
            ->willReturn($purchaseRepository);

        $eventEmitter = $this->createMock(EmitterInterface::class);
        $eventEmitter->expects($this->once())
            ->method("emit")
            ->with($this->isInstanceOf(RequestAccessTokenEvent::class));

        ["private" => $privateKey] = $this->generateKeypair(self::RSA_KEYPAIR_PARAMS);

        $grant = new GoogleNonConsumable($productRepository, $serviceFactory);
        $grant->setClientRepository($clientRepository);
        $grant->setAccessTokenRepository($accessTokenRepository);
        $grant->setScopeRepository($scopeRepository);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setPrivateKey(new CryptKey($privateKey));
        $grant->setEmitter($eventEmitter);

        $serverRequest = (new ServerRequest())->withParsedBody([
            "client_id"         => $clientId,
            "purchase_token"    => $purchaseToken,
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
        $purchaseToken = "IJirr23bCwjk6z8H9URO0CRC9xNHGB9Z";

        $clientRepository = $this->createStub(ClientRepositoryInterface::class);
        $scopeRepository = $this->createStub(ScopeRepositoryInterface::class);
        $accessTokenRepository = $this->createStub(AccessTokenRepositoryInterface::class);
        $productRepository = $this->createStub(NonConsumableRepositoryInterface::class);
        $serviceFactory = $this->createStub(GoogleProductPurchaseFactoryInterface::class);
        $eventEmitter = $this->createStub(EmitterInterface::class);

        ["private" => $privateKey] = $this->generateKeypair(self::RSA_KEYPAIR_PARAMS);

        $grant = new GoogleNonConsumable($productRepository, $serviceFactory);
        $grant->setClientRepository($clientRepository);
        $grant->setAccessTokenRepository($accessTokenRepository);
        $grant->setScopeRepository($scopeRepository);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setPrivateKey(new CryptKey($privateKey));
        $grant->setEmitter($eventEmitter);

        $serverRequest = (new ServerRequest())->withParsedBody([
            "purchase_token"    => $purchaseToken,
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
        $purchaseToken = "IJirr23bCwjk6z8H9URO0CRC9xNHGB9Z";

        $clientRepository = $this->createMock(ClientRepositoryInterface::class);
        $clientRepository->expects($this->once())
            ->method("getClientEntity")
            ->with($clientId)
            ->willReturn(null);

        $scopeRepository = $this->createStub(ScopeRepositoryInterface::class);
        $accessTokenRepository = $this->createStub(AccessTokenRepositoryInterface::class);
        $productRepository = $this->createStub(NonConsumableRepositoryInterface::class);
        $serviceFactory = $this->createStub(GoogleProductPurchaseFactoryInterface::class);
        $eventEmitter = $this->createMock(EmitterInterface::class);
        $eventEmitter->expects($this->once())
            ->method("emit")
            ->with($this->isInstanceOf(RequestEvent::class));

        ["private" => $privateKey] = $this->generateKeypair(self::RSA_KEYPAIR_PARAMS);

        $grant = new GoogleNonConsumable($productRepository, $serviceFactory);
        $grant->setClientRepository($clientRepository);
        $grant->setAccessTokenRepository($accessTokenRepository);
        $grant->setScopeRepository($scopeRepository);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setPrivateKey(new CryptKey($privateKey));
        $grant->setEmitter($eventEmitter);

        $serverRequest = (new ServerRequest())->withParsedBody([
            "client_id"         => $clientId,
            "purchase_token"    => $purchaseToken,
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
        $purchaseToken = "IJirr23bCwjk6z8H9URO0CRC9xNHGB9Z";

        $clientEntity = $this->createStub(ClientEntityInterface::class);
        $clientRepository = $this->createMock(ClientRepositoryInterface::class);
        $clientRepository->expects($this->once())
            ->method("getClientEntity")
            ->with($clientId)
            ->willReturn($clientEntity);

        $scopeRepository = $this->createStub(ScopeRepositoryInterface::class);
        $accessTokenRepository = $this->createStub(AccessTokenRepositoryInterface::class);
        $productRepository = $this->createStub(NonConsumableRepositoryInterface::class);

        $serviceFactory = $this->createMock(GoogleProductPurchaseFactoryInterface::class);
        $serviceFactory->expects($this->once())
            ->method("getRepositoryForClient")
            ->with($clientEntity)
            ->willReturn(null);

        $eventEmitter = $this->createStub(EmitterInterface::class);

        ["private" => $privateKey] = $this->generateKeypair(self::RSA_KEYPAIR_PARAMS);

        $grant = new GoogleNonConsumable($productRepository, $serviceFactory);
        $grant->setClientRepository($clientRepository);
        $grant->setAccessTokenRepository($accessTokenRepository);
        $grant->setScopeRepository($scopeRepository);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setPrivateKey(new CryptKey($privateKey));
        $grant->setEmitter($eventEmitter);

        $serverRequest = (new ServerRequest())->withParsedBody([
            "client_id"         => $clientId,
            "purchase_token"    => $purchaseToken,
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
        $purchaseToken = "IJirr23bCwjk6z8H9URO0CRC9xNHGB9Z";

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
        $purchaseRepository = $this->createStub(ProductPurchaseRepository::class);

        $serviceFactory = $this->createMock(GoogleProductPurchaseFactoryInterface::class);
        $serviceFactory->expects($this->once())
            ->method("getRepositoryForClient")
            ->with($clientEntity)
            ->willReturn($purchaseRepository);

        $eventEmitter = $this->createStub(EmitterInterface::class);

        ["private" => $privateKey] = $this->generateKeypair(self::RSA_KEYPAIR_PARAMS);

        $grant = new GoogleNonConsumable($productRepository, $serviceFactory);
        $grant->setClientRepository($clientRepository);
        $grant->setAccessTokenRepository($accessTokenRepository);
        $grant->setScopeRepository($scopeRepository);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setPrivateKey(new CryptKey($privateKey));
        $grant->setEmitter($eventEmitter);

        $serverRequest = (new ServerRequest())->withParsedBody([
            "client_id"         => $clientId,
            "purchase_token"    => $purchaseToken,
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
        $purchaseToken = "IJirr23bCwjk6z8H9URO0CRC9xNHGB9Z";

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
            ->with([$scopeEntity], "urn:uuid:ea31e77f-cb72-486f-b5c4-deef43e839f3", $clientEntity)
            ->willReturn([$scopeEntity]);

        $accessTokenRepository = $this->createStub(AccessTokenRepositoryInterface::class);

        $productRepository = $this->createMock(NonConsumableRepositoryInterface::class);
        $productRepository->expects($this->once())
            ->method("getNonConsumableFromScope")
            ->with([$scopeEntity])
            ->willReturn(null);

        // @phpstan-ignore method.unresolvableReturnType
        $purchaseRepository = $this->createStub(ProductPurchaseRepository::class);

        $serviceFactory = $this->createMock(GoogleProductPurchaseFactoryInterface::class);
        $serviceFactory->expects($this->once())
            ->method("getRepositoryForClient")
            ->with($clientEntity)
            ->willReturn($purchaseRepository);

        $eventEmitter = $this->createStub(EmitterInterface::class);

        ["private" => $privateKey] = $this->generateKeypair(self::RSA_KEYPAIR_PARAMS);

        $grant = new GoogleNonConsumable($productRepository, $serviceFactory);
        $grant->setClientRepository($clientRepository);
        $grant->setAccessTokenRepository($accessTokenRepository);
        $grant->setScopeRepository($scopeRepository);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setPrivateKey(new CryptKey($privateKey));
        $grant->setEmitter($eventEmitter);

        $serverRequest = (new ServerRequest())->withParsedBody([
            "client_id"         => $clientId,
            "purchase_token"    => $purchaseToken,
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
            ->with([$scopeEntity], "urn:uuid:ea31e77f-cb72-486f-b5c4-deef43e839f3", $clientEntity)
            ->willReturn([$scopeEntity]);

        $accessTokenRepository = $this->createStub(AccessTokenRepositoryInterface::class);

        $product = $this->createStub(NonConsumableEntityInterface::class);
        $productRepository = $this->createMock(NonConsumableRepositoryInterface::class);
        $productRepository->expects($this->once())
            ->method("getNonConsumableFromScope")
            ->with([$scopeEntity])
            ->willReturn($product);

        // @phpstan-ignore method.unresolvableReturnType
        $purchaseRepository = $this->createStub(ProductPurchaseRepository::class);

        $serviceFactory = $this->createMock(GoogleProductPurchaseFactoryInterface::class);
        $serviceFactory->expects($this->once())
            ->method("getRepositoryForClient")
            ->with($clientEntity)
            ->willReturn($purchaseRepository);

        $eventEmitter = $this->createStub(EmitterInterface::class);

        ["private" => $privateKey] = $this->generateKeypair(self::RSA_KEYPAIR_PARAMS);

        $grant = new GoogleNonConsumable($productRepository, $serviceFactory);
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
        $purchaseToken = "IJirr23bCwjk6z8H9URO0CRC9xNHGB9Z";

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
            ->with([$scopeEntity], "urn:uuid:ea31e77f-cb72-486f-b5c4-deef43e839f3", $clientEntity)
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
        $purchaseRepository = $this->createMock(ProductPurchaseRepository::class);
        $purchaseRepository->expects($this->once())
            ->method("get")
            ->willThrowException(new StoreAuthException("Failed to fetch transaction history from apple storekit endpoint. Response status=401"));

        $serviceFactory = $this->createMock(GoogleProductPurchaseFactoryInterface::class);
        $serviceFactory->expects($this->once())
            ->method("getRepositoryForClient")
            ->with($clientEntity)
            ->willReturn($purchaseRepository);

        $eventEmitter = $this->createStub(EmitterInterface::class);

        ["private" => $privateKey] = $this->generateKeypair(self::RSA_KEYPAIR_PARAMS);

        $grant = new GoogleNonConsumable($productRepository, $serviceFactory);
        $grant->setClientRepository($clientRepository);
        $grant->setAccessTokenRepository($accessTokenRepository);
        $grant->setScopeRepository($scopeRepository);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setPrivateKey(new CryptKey($privateKey));
        $grant->setEmitter($eventEmitter);

        $serverRequest = (new ServerRequest())->withParsedBody([
            "client_id"         => $clientId,
            "purchase_token"    => $purchaseToken,
            "scope"             => $scope,
        ]);

        $responseType = $this->createStub(ResponseTypeInterface::class);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionMessage("The authorization server encountered an unexpected condition which prevented it from fulfilling the request: Failed to retrieve product purchase status");
        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval("PT5M"));
    }

    public function testPurchaseInvalidState(): void
    {
        $clientId = "test-client-72b86b49";
        $scope = "product-1";
        $sku = "com.example.product-1";
        $purchaseToken = "IJirr23bCwjk6z8H9URO0CRC9xNHGB9Z";

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
            ->with([$scopeEntity], "urn:uuid:ea31e77f-cb72-486f-b5c4-deef43e839f3", $clientEntity)
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
        $purchaseRepository = $this->createMock(ProductPurchaseRepository::class);
        $purchaseRepository->expects($this->once())
            ->method("get")
            ->with($sku, $purchaseToken)
            ->willReturn([
                "acknowledgementState" => 1,
                "purchaseState" => 1,
            ]);

        $serviceFactory = $this->createMock(GoogleProductPurchaseFactoryInterface::class);
        $serviceFactory->expects($this->once())
            ->method("getRepositoryForClient")
            ->with($clientEntity)
            ->willReturn($purchaseRepository);

        $eventEmitter = $this->createStub(EmitterInterface::class);

        ["private" => $privateKey] = $this->generateKeypair(self::RSA_KEYPAIR_PARAMS);

        $grant = new GoogleNonConsumable($productRepository, $serviceFactory);
        $grant->setClientRepository($clientRepository);
        $grant->setAccessTokenRepository($accessTokenRepository);
        $grant->setScopeRepository($scopeRepository);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setPrivateKey(new CryptKey($privateKey));
        $grant->setEmitter($eventEmitter);

        $serverRequest = (new ServerRequest())->withParsedBody([
            "client_id"         => $clientId,
            "purchase_token"    => $purchaseToken,
            "scope"             => $scope,
        ]);

        $responseType = $this->createStub(ResponseTypeInterface::class);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionMessage("The user credentials were incorrect.");
        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval("PT5M"));
    }

    public function testAcknowledgeFailure(): void
    {
        $clientId = "test-client-72b86b49";
        $scope = "product-1";
        $sku = "com.example.product-1";
        $purchaseToken = "IJirr23bCwjk6z8H9URO0CRC9xNHGB9Z";

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
            ->with([$scopeEntity], "urn:uuid:ea31e77f-cb72-486f-b5c4-deef43e839f3", $clientEntity)
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
        $purchaseRepository = $this->createMock(ProductPurchaseRepository::class);
        $purchaseRepository->expects($this->once())
            ->method("get")
            ->with($sku, $purchaseToken)
            ->willReturn([
                "acknowledgementState" => 0,
                "purchaseState" => 0,
            ]);
        $purchaseRepository->expects($this->once())
            ->method("acknowledge")
            ->with($sku, $purchaseToken)
            ->willThrowException(new StoreAuthException("Failed to acknowledge product purchase at google endpoint. Response status=401"));

        $serviceFactory = $this->createMock(GoogleProductPurchaseFactoryInterface::class);
        $serviceFactory->expects($this->once())
            ->method("getRepositoryForClient")
            ->with($clientEntity)
            ->willReturn($purchaseRepository);

        $eventEmitter = $this->createMock(EmitterInterface::class);
        $eventEmitter->expects($this->once())
            ->method("emit")
            ->with($this->isInstanceOf(RequestAccessTokenEvent::class));

        ["private" => $privateKey] = $this->generateKeypair(self::RSA_KEYPAIR_PARAMS);

        $grant = new GoogleNonConsumable($productRepository, $serviceFactory);
        $grant->setClientRepository($clientRepository);
        $grant->setAccessTokenRepository($accessTokenRepository);
        $grant->setScopeRepository($scopeRepository);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setPrivateKey(new CryptKey($privateKey));
        $grant->setEmitter($eventEmitter);

        $serverRequest = (new ServerRequest())->withParsedBody([
            "client_id"         => $clientId,
            "purchase_token"    => $purchaseToken,
            "scope"             => $scope,
        ]);

        $responseType = $this->createMock(ResponseTypeInterface::class);
        $responseType->expects($this->once())
            ->method("setAccessToken")
            ->with($accessTokenEntity);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionMessage("The authorization server encountered an unexpected condition which prevented it from fulfilling the request: Failed to acknowledge product purchase status");
        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval("PT5M"));
    }
}
