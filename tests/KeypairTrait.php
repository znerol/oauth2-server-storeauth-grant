<?php

declare(strict_types=1);

namespace StoreAuth\Tests;

trait KeypairTrait
{
    protected const EC_KEYPAIR_PARAMS = [
        "curve_name" => "prime256v1",
        "private_key_type" => OPENSSL_KEYTYPE_EC,
    ];

    /**
     * Returns keypair encoded in PEM format.
     *
     * @param ?array{
     *    "private_key_type": int,
     *    "curve_name"?: string,
     *    "private_key_bits"?: int,
     * } $options
     *
     * @return array{
     *     "private": non-empty-string,
     *     "public": non-empty-string,
     * }
     */
    private function generateKeypair(?array $options = null): array
    {
        $keypair = openssl_pkey_new($options);
        $this->assertNotFalse($keypair);

        $result = openssl_pkey_get_details($keypair);
        $this->assertNotFalse($result);
        ["key" => $publicPem] = $result;

        $privatePem = "";
        $result = openssl_pkey_export($keypair, $privatePem);
        $this->assertNotFalse($result);

        return ["private" => $privatePem, "public" => $publicPem];
    }
}
