<?php

declare(strict_types=1);

namespace StoreAuth\Tests;

use PHPUnit\Framework\Attributes\After;
use RuntimeException;

trait TempfileTrait
{
    /**
     * @var non-empty-string[]
     */
    private array $temporaryFiles = [];

    /**
     * @return non-empty-string
     */
    protected function getTempfile(): string
    {
        $tempfile = tempnam(sys_get_temp_dir(), "phpunit");
        if (!$tempfile) {
            throw new RuntimeException("Failed to create temporary file");
        }
        $this->temporaryFiles[] = $tempfile;
        return $tempfile;
    }

    #[After]
    protected function cleanupTempfiles(): void
    {
        foreach ($this->temporaryFiles as $tempfile) {
            @unlink($tempfile);
        }
    }
}
