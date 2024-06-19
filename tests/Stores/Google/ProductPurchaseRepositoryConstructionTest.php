<?php

declare(strict_types=1);

namespace StoreAuth\Tests\Stores\Google;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use StoreAuth\Stores\Google\GoogleAccount;
use StoreAuth\Stores\Google\ProductPurchaseRepository;

#[CoversClass(className: ProductPurchaseRepository::class)]
#[UsesClass(className: GoogleAccount::class)]
final class ProductPurchaseRepositoryConstructionTest extends TestCase
{
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
        $repository = ProductPurchaseRepository::fromConfig('com.example.app', $config, $httpClient, $requestFactory);
        $this->assertInstanceOf(ProductPurchaseRepository::class, $repository);
    }
}
