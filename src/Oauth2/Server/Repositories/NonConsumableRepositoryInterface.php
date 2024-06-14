<?php

declare(strict_types=1);

namespace StoreAuth\Oauth2\Server\Repositories;

use League\OAuth2\Server\Repositories\RepositoryInterface;
use StoreAuth\Oauth2\Server\Entities\NonConsumableEntityInterface;

/**
 * Repository for non-consumable store product.
 */
interface NonConsumableRepositoryInterface extends RepositoryInterface
{
    /**
     * Given a list of scopes, return the matching product.
     *
     * @param \League\OAuth2\Server\Entities\ScopeEntityInterface[] $scopes
     *   One or more scopes identifying the product.
     */
    public function getNonConsumableFromScope(array $scopes): ?NonConsumableEntityInterface;
}
