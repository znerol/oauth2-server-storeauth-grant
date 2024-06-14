<?php

declare(strict_types=1);

namespace StoreAuth\Stores\Google;

use Lcobucci\JWT\Token;
use Psr\Http\Message\StreamInterface;

/**
 * Implements a JWT grant request body as a http-message stream.
 */
final class JwtGrantRequestBody implements StreamInterface
{
    private const AUTH_TOKEN_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    /**
     * The underlying memory stream.
     *
     * @var resource
     */
    private $stream;

    /**
     * Size of the underlying memory stream.
     */
    private int $size = 0;

    public function __construct(Token $token)
    {
        $stream = fopen("php://memory", "r+");
        assert($stream !== false);
        $this->stream = $stream;

        $params = [
            implode("=", ["grant_type", urlencode(self::AUTH_TOKEN_GRANT_TYPE)]),
            implode("=", ["assertion", urlencode($token->toString())]),
        ];

        $size = fwrite($this->stream, implode("&", $params));
        assert($size !== false);
        $this->size = $size;

        rewind($this->stream);
    }

    /**
     * {@inheritdoc}
     */
    public function __toString(): string
    {
        $this->rewind();
        return $this->getContents();
    }

    /**
     * {@inheritdoc}
     */
    public function close(): void
    {
        fclose($this->stream);
    }

    /**
     * {@inheritdoc}
     */
    public function detach()
    {
        return $this->stream;
    }

    /**
     * {@inheritdoc}
     */
    public function getSize(): ?int
    {
        return $this->size;
    }

    /**
     * {@inheritdoc}
     */
    public function tell(): int
    {
        $result = ftell($this->stream);
        assert($result !== false);
        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function eof(): bool
    {
        return feof($this->stream);
    }

    /**
     * {@inheritdoc}
     */
    public function isSeekable(): bool
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        fseek($this->stream, $offset, $whence);
    }

    /**
     * {@inheritdoc}
     */
    public function rewind(): void
    {
        rewind($this->stream);
    }

    /**
     * {@inheritdoc}
     */
    public function isWritable(): bool
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function write(string $string): int
    {
        $result = fwrite($this->stream, $string);
        assert($result !== false);
        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function isReadable(): bool
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function read(int $length): string
    {
        assert($length > 0);
        $result = fread($this->stream, $length);
        assert($result !== false);
        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function getContents(): string
    {
        $result = stream_get_contents($this->stream);
        assert($result !== false);
        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function getMetadata(?string $key = null)
    {
        $metadata = stream_get_meta_data($this->stream);
        return $key === null ? $metadata : $metadata[$key];
    }
}
