Google Billing / Apple StoreKit OAuth2 Grant Extension for PHP OAuth 2.0 Server
===============================================================================

An OAuth 2 [extension grant][rfc6749-4.5] which validates a Google Billing purchase or an Apple StoreKit transaction and returns an access token restricted to the specified SKU/product.

Dependencies
------------

Some PSR-18 HTTP client.

Flow (Android Billing)
----------------------

The client sends a POST request with following body parameters to the authorization server:

* `grant_type` with the value `urn:uuid:ea31e77f-cb72-486f-b5c4-deef43e839f3`
* `client_id` with the client’s ID
* `scope` with a space-delimited list of requested scope permissions
* `purchase_token` with the android billing purchase token

The authorization server will respond with a JSON object containing the following properties:

* `token_type` with the value `Bearer`
* `expires_in` with an integer representing the TTL of the access token
* `access_token` a JWT signed with the authorization server’s private key

Flow (Apple StoreKit)
---------------------

The client sends a POST request with following body parameters to the authorization server:

* `grant_type` with the value: `urn:uuid:c7e545a5-d72b-4294-a173-bb1858aae099`
* `client_id` with the client’s ID
* `scope` with a space-delimited list of requested scope permissions
* `transaction_id` with the StoreKit transaction id

The authorization server will respond with a JSON object containing the following properties:

* `token_type` with the value `Bearer`
* `expires_in` with an integer representing the TTL of the access token
* `access_token` a JWT signed with the authorization server’s private key

Setup
-----

Wherever you initialize your objects, initialize a new instance of the authorization server and bind the storage interfaces and authorization code grant:

```PHP
// Init our repositories
$clientRepository = new ClientRepository(); // instance of ClientRepositoryInterface
$scopeRepository = new ScopeRepository(); // instance of ScopeRepositoryInterface
$accessTokenRepository = new AccessTokenRepository(); // instance of AccessTokenRepositoryInterface

// Path to public and private keys
$privateKey = 'file://path/to/private.key';
//$privateKey = new CryptKey('file://path/to/private.key', 'passphrase'); // if private key has a pass phrase
$encryptionKey = 'lxZFUEsBCJ2Yb14IF2ygAHI5N4+ZAUXXaSeeJm6+twsUmIen'; // generate using base64_encode(random_bytes(32))

// Setup the authorization server
$server = new \League\OAuth2\Server\AuthorizationServer(
    $clientRepository,
    $accessTokenRepository,
    $scopeRepository,
    $privateKey,
    $encryptionKey
);
```

For google non-consumables:

```PHP
// Init non-consumable product repository
$productRepository = ProductRepository() // instance of NonConsumableRepositoryInterface

// Init google client factory
$googleClientFactory = GoogleClientFactory() // instance of GoogleProductPurchaseFactoryInterface

// Enable the Android purchases product grant on the server
$packageName = 'com.some.thing';
$clientCredentials = // path to google api service account client credentials
$server->enableGrantType(
    new \StoreAuth\OAuth2\Server\Grant\GoogleNonConsumable($productRepository, $googleClientFactory),
    new \DateInterval('PT1H') // access tokens will expire after 1 hour
);
```

For apple non-consumables:

```PHP
// Init non-consumable product repository
$productRepository = ProductRepository() // instance of NonConsumableRepositoryInterface

// Init apple client factory
$appleClientFactory = AppleClientFactory() // instance of AppleMostRecentTransactionFactoryInterface

// Enable the Apple transactions grant on the server
$server->enableGrantType(
    new \StoreAuth\OAuth2\Server\Grant\AppleNonConsumable($productRepository, $appleClientFactory),
    new \DateInterval('PT1H') // access tokens will expire after 1 hour
);
```

License
-------

[MIT License][mit]

[rfc6749-4.5]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.5
[mit]: https://opensource.org/license/mit
