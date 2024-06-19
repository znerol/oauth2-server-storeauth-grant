<?php

declare(strict_types=1);

namespace StoreAuth\Tests\JWT\Validation\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation as JWT;
use Lcobucci\JWT\Validation\ConstraintViolation;

final class HasHeaderWithValue implements JWT\Constraint
{
    /**
     * @param non-empty-string $header
     */
    public function __construct(
        private readonly string $header,
        private readonly mixed $expectedValue
    ) {
    }

    public function assert(Token $token): void
    {
        $headers = $token->headers();

        if (!$headers->has($this->header)) {
            throw ConstraintViolation::error('The token does not have the header "' . $this->header . '"', $this);
        }

        if ($headers->get($this->header) !== $this->expectedValue) {
            throw ConstraintViolation::error(
                'The header "' . $this->header . '" does not have the expected value',
                $this,
            );
        }
    }
}
