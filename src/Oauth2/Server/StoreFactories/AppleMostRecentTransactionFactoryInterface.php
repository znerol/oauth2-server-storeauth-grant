<?php

declare(strict_types=1);

namespace StoreAuth\Oauth2\Server\StoreFactories;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use StoreAuth\Stores\Apple\MostRecentTransactionRepository;

interface AppleMostRecentTransactionFactoryInterface
{
    public function getRepositoryForClient(ClientEntityInterface $client): ?MostRecentTransactionRepository;
}
