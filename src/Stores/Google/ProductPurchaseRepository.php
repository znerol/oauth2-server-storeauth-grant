<?php

declare(strict_types=1);

namespace StoreAuth\Stores\Google;

use JsonException;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use RuntimeException;
use StoreAuth\Exceptions\StoreAuthException;
use StoreAuth\Oauth2\ServiceAccount;

final class ProductPurchaseRepository
{
    /**
     * Constructs new google product purchase repository from config.
     *
     * @param string $packageId
     *   The app package id.
     *
     * @param array{
     *     "client_email": non-empty-string,
     *     "private_key": non-empty-string,
     *     "private_key_id": non-empty-string
     *   } $config Service account configuration as parsed from the json config file.
     */
    public static function fromConfig(
        string $packageId,
        array $config,
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        ?ServiceAccount $serviceAccount = null
    ): static {
        return new static(
            packageId: $packageId,
            httpClient: $httpClient,
            requestFactory: $requestFactory,
            serviceAccount: $serviceAccount ?? GoogleAccount::fromConfig($config, $httpClient, $requestFactory),
        );
    }

    /**
     * Constructs new google product purchase repository.
     */
    public function __construct(
        private string $packageId,
        private ClientInterface $httpClient,
        private RequestFactoryInterface $requestFactory,
        private ServiceAccount $serviceAccount
    ) {
    }

    /**
     * Return a ProductPurchase resource.
     *
     * Indicates the status of a user's inapp product purchase.
     *
     * @param string $productId
     *   The in-app-purchase product identifier (com.exmaple.some-item)
     * @param string $purchaseToken
     *   The purchase token identifying an individual transaction.
     *
     * @return array{
     *   "acknowledgementState": int,
     *   "consumptionState": int,
     *   "developerPayload": string,
     *   "kind": string,
     *   "orderId": string,
     *   "purchaseState": int,
     *   "purchaseTimeMillis": string,
     *   "purchaseType": int,
     *   "regionCode": string,
     * }
     *
     * @throws \StoreAuth\Exceptions\StoreAuthException
     *
     * @see https://developers.google.com/android-publisher/api-ref/rest/v3/purchases.products
     */
    public function get(string $productId, string $purchaseToken): array
    {
        $resourceUrl = implode("/", [
            "https://androidpublisher.googleapis.com/androidpublisher/v3/applications",
            $this->packageId, "purchases", "products", $productId, "tokens", $purchaseToken
        ]);
        $bearerToken = $this->serviceAccount->getBearerToken();
        $statusRequest = $this->requestFactory->createRequest("GET", $resourceUrl)
            ->withHeader("Authorization", "Bearer $bearerToken");

        $statusResponse = $this->httpClient->sendRequest($statusRequest);
        $responseCode = $statusResponse->getStatusCode();
        if ($responseCode !== 200) {
            throw new StoreAuthException("Failed to fetch product purchase from google endpoint. Response status=$responseCode");
        }

        try {
            $result = json_decode(
                json: $statusResponse->getBody()->getContents(),
                associative: true,
                flags: JSON_THROW_ON_ERROR
            );
        } catch (RuntimeException | JsonException $e) {
            throw new StoreAuthException("Unexpected data returned from google product purchase endpoint.", previous: $e);
        }

        assert(is_array($result));
        assert(is_int($result["acknowledgementState"]));
        assert(is_int($result["consumptionState"]));
        assert(is_string($result["developerPayload"]));
        assert(is_string($result["kind"]));
        assert(is_string($result["orderId"]));
        assert(is_int($result["purchaseState"]));
        assert(is_string($result["purchaseTimeMillis"]));
        assert(is_int($result["purchaseType"]));
        assert(is_string($result["regionCode"]));
        return $result;
    }

    /**
     * Acknowledge a ProductPurchase resource.
     *
     * Indicates the status of a user's inapp product purchase.
     *
     * @param string $productId
     *   The in-app-purchase product identifier (com.exmaple.some-item)
     * @param string $purchaseToken
     *   The purchase token identifying an individual transaction.
     *
     * @see https://developers.google.com/android-publisher/api-ref/rest/v3/purchases.products
     */
    public function acknowledge(string $productId, string $purchaseToken): void
    {
        $resourceUrl = implode("/", [
            "https://androidpublisher.googleapis.com/androidpublisher/v3/applications",
            $this->packageId, "purchases", "products", $productId, "tokens", $purchaseToken
        ]);
        $bearerToken = $this->serviceAccount->getBearerToken();
        $statusRequest = $this->requestFactory
            ->createRequest("POST", implode(":", [$resourceUrl, "acknowledge"]))
            ->withHeader("Authorization", "Bearer $bearerToken");

        $statusResponse = $this->httpClient->sendRequest($statusRequest);
        $responseCode = $statusResponse->getStatusCode();
        if ($responseCode !== 200) {
            throw new StoreAuthException("Failed to acknowledge product purchase at google endpoint. Response status=$responseCode");
        }
    }
}
