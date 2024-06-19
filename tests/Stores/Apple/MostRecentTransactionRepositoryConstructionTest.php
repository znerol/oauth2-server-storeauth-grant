<?php

declare(strict_types=1);

namespace StoreAuth\Tests\Stores\Apple;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use StoreAuth\JWT\Validation\Constraint\SignedWithCertificateChain;
use StoreAuth\Oauth2\ServiceAccount;
use StoreAuth\Stores\Apple\MostRecentTransactionRepository;

#[CoversClass(className: MostRecentTransactionRepository::class)]
#[UsesClass(className: SignedWithCertificateChain::class)]
final class MostRecentTransactionRepositoryConstructionTest extends TestCase
{
    public function testConstruction(): void
    {

        $httpClient = $this->createStub(ClientInterface::class);
        $requestFactory = $this->createStub(RequestFactoryInterface::class);
        $serviceAccount = $this->createStub(ServiceAccount::class);
        $repository = MostRecentTransactionRepository::fromConfig($httpClient, $requestFactory, $serviceAccount);
        $this->assertInstanceOf(MostRecentTransactionRepository::class, $repository);
    }
}
