<?php

declare(strict_types=1);

namespace StoreAuth\Oauth2\Server\Grant;

use DateInterval;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Grant\GrantTypeInterface;
use League\OAuth2\Server\RequestAccessTokenEvent;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use StoreAuth\Oauth2\Server\Repositories\NonConsumableRepositoryInterface;
use StoreAuth\Oauth2\Server\StoreFactories\AppleMostRecentTransactionFactoryInterface;

class AppleNonConsumable extends AbstractGrant implements GrantTypeInterface
{
    public function __construct(
        private readonly NonConsumableRepositoryInterface $productRepository,
        private readonly AppleMostRecentTransactionFactoryInterface $serviceFactory
    ) {
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier()
    {
        return "urn:uuid:c7e545a5-d72b-4294-a173-bb1858aae099";
    }

    /**
     * {@inheritdoc}
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    ) {
        // Validate client_id and load associated service account.
        $clientId = $this->getRequestParameter("client_id", $request);
        if ($clientId === null) {
            throw OAuthServerException::invalidRequest("client_id");
        }

        $client = $this->getClientEntityOrFail($clientId, $request);
        $purchaseRepository = $this->serviceFactory->getRepositoryForClient($client);
        if ($purchaseRepository === null) {
            throw OAuthServerException::invalidRequest("client_id");
        }

        // Validate requested scopes
        $scopes = $this->validateScopes($this->getRequestParameter("scope", $request, $this->defaultScope));

        // Finalize the requested scopes
        $finalizedScopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client);

        // Validate product identified by scopes
        $product = $this->productRepository->getNonConsumableFromScope($finalizedScopes);
        if ($product === null) {
            $productLookupScopes = array_map(fn ($scope) => $scope->getIdentifier(), $finalizedScopes);
            throw OAuthServerException::invalidScope(implode(" ", $productLookupScopes));
        }

        // Validate transaction id
        $transactionId = $this->getRequestParameter("transaction_id", $request);
        if ($transactionId === null) {
            throw OAuthServerException::invalidRequest("transaction_id");
        }

        // Retreive purchase
        try {
            $result = $purchaseRepository->get($product->getSku(), $transactionId);
        } catch (RuntimeException $e) {
            throw OAuthServerException::serverError("Failed to retrieve product purchase status", $e);
        }

        // Note: The transaction is valid if it was retrieved successfully.
        // However, any transaction id from a customers entire purchase history
        // can be used in combination with any sku ever purchased by that user
        // to authenticate the call. The product repository should only map
        // request scopes to a non-consumable product. Still, as a measure of
        // defence in depth, ensure that we are not accidently issuing an access
        // token for a different product type.
        if ($result === false || $result["type"] !== "Non-Consumable") {
            throw OAuthServerException::invalidCredentials();
        }

        // Issue and persist access token
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, null, $finalizedScopes);

        // Send event to emitter
        $this->getEmitter()->emit(new RequestAccessTokenEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request, $accessToken));

        // Inject access token into response type
        $responseType->setAccessToken($accessToken);

        return $responseType;
    }
}
