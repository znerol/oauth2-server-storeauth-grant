<?php

declare(strict_types=1);

namespace StoreAuth\Stores\Apple;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Validator;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use RuntimeException;
use StoreAuth\Exceptions\StoreAuthException;
use StoreAuth\JWT\Validation\Constraint\SignedWithCertificateChain;
use StoreAuth\Oauth2\ServiceAccount;

final class MostRecentTransactionRepository
{
    private Parser $parser;

    private Validator $validator;

    /**
     * @param non-empty-string[] $appleTrustAnchors
     */
    public static function fromConfig(
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        ServiceAccount $serviceAccount,
        array $appleTrustAnchors
    ): static {
        $signedWith = new SignedWithCertificateChain(new Sha256(), $appleTrustAnchors);
        return new static(
            httpClient: $httpClient,
            requestFactory: $requestFactory,
            serviceAccount: $serviceAccount,
            constraints: [$signedWith]
        );
    }

    /**
     * Constructs new apple transaction repository.
     *
     * @param \Lcobucci\JWT\Validation\Constraint[] $constraints
     */
    public function __construct(
        private ClientInterface $httpClient,
        private RequestFactoryInterface $requestFactory,
        private ServiceAccount $serviceAccount,
        private array $constraints,
    ) {
        $this->parser = new Parser(new JoseEncoder());
        $this->validator = new Validator();
    }

    /**
     * Returns the most recent non-revoked transaction for the given product.
     *
     * @param string $productId
     *   A product identifier.
     * @param string $transactionId
     *   The identifier for an individual transaction.
     *
     * @return array{
     *   "transactionId": string,
     *   "originalTransactionId": string,
     *   "bundleId": string,
     *   "productId": string,
     *   "purchaseDate": int,
     *   "originalPurchaseDate": int,
     *   "quantity": int,
     *   "type": string,
     *   "inAppOwnershipType": string,
     *   "signedDate": int,
     *   "environment": string,
     *   "transactionReason": string,
     *   "storefront": string,
     *   "storefrontId": string,
     *   "price": int,
     *   "currency": string
     * }|false
     *
     * @throws \StoreAuth\Exceptions\StoreAuthException
     *
     * @see https://developer.apple.com/documentation/appstoreserverapi/get_transaction_history
     */
    public function get(string $productId, string $transactionId): array|false
    {
        $historyUrl = implode("/", [
            "https://api.storekit.itunes.apple.com/inApps/v2/history",
            $transactionId
        ]);
        $historyQuery = implode("&", [
            implode("=", ["productId", urlencode($productId)]),
            implode("=", ["revoked", "false"]),
            implode("=", ["sort", "DESCENDING"])
        ]);
        $bearerToken = $this->serviceAccount->getBearerToken();
        $transactionRequest = $this->requestFactory
            ->createRequest("GET", implode("?", [$historyUrl, $historyQuery]))
            ->withHeader("Authorization", "Bearer $bearerToken");

        $transactionResponse = $this->httpClient->sendRequest($transactionRequest);
        $responseCode = $transactionResponse->getStatusCode();
        if ($responseCode !== 200) {
            throw new StoreAuthException("Failed to fetch transaction history from apple storekit endpoint. Response status=$responseCode");
        }

        $responsePayload = json_decode($transactionResponse->getBody()->getContents(), true);
        if (
            !is_array($responsePayload) ||
            !isset($responsePayload["signedTransactions"]) ||
            !is_array($responsePayload["signedTransactions"])
        ) {
            throw new StoreAuthException("Unexpected data returned from apple storekit transaction history endpoint.");
        }

        $signedTransactions = $responsePayload["signedTransactions"];
        if (count($signedTransactions) === 0) {
            return false;
        }

        $parsedPayload = $this->parser->parse($signedTransactions[0]);
        try {
            $this->validator->assert($parsedPayload, ...$this->constraints);
        } catch (RuntimeException $e) {
            throw new StoreAuthException("Verification failed for data returned from apple storekit transaction history endpoint.", previous: $e);
        }

        assert($parsedPayload instanceof UnencryptedToken);
        $result = $parsedPayload->claims()->all();
        assert(is_string($result["transactionId"]));
        assert(is_string($result["originalTransactionId"]));
        assert(is_string($result["bundleId"]));
        assert(is_string($result["productId"]));
        assert(is_int($result["purchaseDate"]));
        assert(is_int($result["originalPurchaseDate"]));
        assert(is_int($result["quantity"]));
        assert(is_string($result["type"]));
        assert(is_string($result["inAppOwnershipType"]));
        assert(is_int($result["signedDate"]));
        assert(is_string($result["environment"]));
        assert(is_string($result["transactionReason"]));
        assert(is_string($result["storefront"]));
        assert(is_string($result["storefrontId"]));
        assert(is_int($result["price"]));
        assert(is_string($result["currency"]));
        return $result;
    }
}
