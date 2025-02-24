<?php

declare(strict_types=1);

namespace StoreAuth\Tests\PHPUnit;

/**
 * @see https://github.com/sebastianbergmann/phpunit/pull/5759
 */
class ClosureMock
{
    public function __invoke(): mixed
    {
        return null;
    }
}
