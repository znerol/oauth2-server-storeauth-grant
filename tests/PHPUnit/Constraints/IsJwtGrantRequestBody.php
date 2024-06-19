<?php

declare(strict_types=1);

namespace StoreAuth\Tests\PHPUnit\Constraints;

use Lcobucci\JWT\JwtFacade;
use Lcobucci\JWT\Validation as JWT;
use PHPUnit\Framework\Constraint\Constraint;
use Psr\Http\Message\StreamInterface;

final class IsJwtGrantRequestBody extends Constraint
{
    /**
     * @var \Lcobucci\JWT\Validation\Constraint[]
     */
    private array $constraints;

    public function __construct(
        private JWT\SignedWith $signedWith,
        private JWT\ValidAt $validAt,
        JWT\Constraint ...$constraints
    ) {
        $this->constraints = $constraints;
    }

    protected function matches(mixed $other): bool
    {
        assert($other instanceof StreamInterface);

        $params = [];
        parse_str($other->getContents(), $params);
        if (!isset($params["grant_type"]) || $params["grant_type"] !== "urn:ietf:params:oauth:grant-type:jwt-bearer") {
            return false;
        }

        if (!isset($params["assertion"]) || !is_string($params["assertion"]) || strlen($params["assertion"]) < 1) {
            return false;
        }

        $token = $params["assertion"];
        $facade = new JwtFacade();
        try {
            $facade->parse($token, $this->signedWith, $this->validAt, ...$this->constraints);
            return true;
        } catch (JWT\RequiredConstraintsViolated) {
            return false;
        }
    }

    /**
     * Returns a string representation of the constraint.
     */
    public function toString(): string
    {
        return 'is a jwt grant request body';
    }
}
