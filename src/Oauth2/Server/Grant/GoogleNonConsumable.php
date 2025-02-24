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
use StoreAuth\Oauth2\Server\StoreFactories\GoogleProductPurchaseFactoryInterface;

class GoogleNonConsumable extends AbstractGrant implements GrantTypeInterface
{
    public function __construct(
        private readonly NonConsumableRepositoryInterface $productRepository,
        private readonly GoogleProductPurchaseFactoryInterface $serviceFactory
    ) {
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier(): string
    {
        return "urn:uuid:ea31e77f-cb72-486f-b5c4-deef43e839f3";
    }

    /**
     * {@inheritdoc}
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    ): ResponseTypeInterface {
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
        $scopeParam = $this->getRequestParameter("scope", $request, $this->defaultScope);
        assert(is_string($scopeParam));
        $scopes = $this->validateScopes($scopeParam);

        // Finalize the requested scopes
        $finalizedScopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client);

        // Validate product identified by scopes
        $product = $this->productRepository->getNonConsumableFromScope($finalizedScopes);
        if ($product === null) {
            $productLookupScopes = array_map(fn ($scope) => $scope->getIdentifier(), $finalizedScopes);
            throw OAuthServerException::invalidScope(implode(" ", $productLookupScopes));
        }

        // Validate purchase token for the product
        $purchaseToken = $this->getRequestParameter("purchase_token", $request);
        if ($purchaseToken === null) {
            throw OAuthServerException::invalidRequest("purchase_token");
        }

        // Retreive purchase
        $productSku = $product->getSku();
        try {
            $statusPayload = $purchaseRepository->get($productSku, $purchaseToken);
        } catch (RuntimeException $e) {
            throw OAuthServerException::serverError("Failed to retrieve product purchase status", $e);
        }

        // Validate purchase
        // https://developer.android.com/google/play/billing/security#verify
        if ($statusPayload["purchaseState"] !== 0) {
            // purchase state is not PURCHASED
            throw OAuthServerException::invalidCredentials();
        }

        // Issue and persist access token
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, null, $finalizedScopes);

        // Send event to emitter
        $this->getEmitter()->emit(new RequestAccessTokenEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request, $accessToken));

        // Inject access token into response type
        $responseType->setAccessToken($accessToken);

        // Acknowledge the purchase.
        // https://developer.android.com/google/play/billing/integrate#process
        if ($statusPayload["acknowledgementState"] === 0) {
            try {
                $purchaseRepository->acknowledge($productSku, $purchaseToken);
            } catch (RuntimeException $e) {
                throw OAuthServerException::serverError("Failed to acknowledge product purchase status", $e);
            }
        }

        return $responseType;
    }
}
