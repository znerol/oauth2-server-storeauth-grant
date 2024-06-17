<?php

declare(strict_types=1);

namespace StoreAuth\Oauth2;

/**
 * Represents an API service account.
 */
interface ServiceAccount
{
    /**
     * @return non-empty-string
     *
     * @throws \StoreAuth\Exceptions\StoreAuthException
     */
    public function getBearerToken(): string;
}
