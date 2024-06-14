<?php

declare(strict_types=1);

namespace StoreAuth\Oauth2\Server\Entities;

interface NonConsumableEntityInterface
{
    /**
     * Returns the product id for this non-consumable item item.
     */
    public function getSku(): string;
}
