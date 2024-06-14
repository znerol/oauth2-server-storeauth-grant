<?php

declare(strict_types=1);

namespace StoreAuth\Oauth2\Server\StoreFactories;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use StoreAuth\Stores\Google\ProductPurchaseRepository;

interface GoogleProductPurchaseFactoryInterface
{
    public function getRepositoryForClient(ClientEntityInterface $client): ?ProductPurchaseRepository;
}
