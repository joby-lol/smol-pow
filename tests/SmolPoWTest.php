<?php

/**
 * smolPoW
 * https://github.com/joby-lol/smol-pow
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\PoW;

use Generator;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class SmolPoWTest extends TestCase
{

    public function test_instantiation(): void
    {
        $pow = new SmolPoW('secret');
        $this->assertInstanceOf(SmolPoW::class, $pow);
    }

    public function test_instantiation_disabled_algorithm(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new SmolPoW('secret', 'md5');
    }

    public function test_instantiation_unavailable_algorithm(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new SmolPoW('secret', 'smolpow', allowed_algorithms: ['smolpow']);
    }

    public function test_challenge_strings_different(): void
    {
        $pow = new SmolPoW('secret');
        $this->assertNotEquals(
            $pow->challengeString('https://example.com'),
            $pow->challengeString('https://example.com')
        );
    }

    public function test_invalid_base64(): void
    {
        $pow = new SmolPoW('secret');
        $this->assertFalse(
            $pow->validateCookieValue('abcdefgh|*****')
        );
    }

    public function test_invalid_cookie_format(): void
    {
        $pow = new SmolPow('secret');
        $this->assertFalse(
            $pow->validateCookieValue('abcdefgh')
        );
        $this->assertFalse(
            $pow->validateCookieValue('abcdefgh|abcdefgh|abcdefgh')
        );
    }

    #[DataProvider('csvDataProvider')]
    public function test_examples(
        string $expected_value,
        string $description,
        string $algorithm,
        string $iterations,
        string $expiration,
        string $secret,
        string $challenge_string,
        string $solution,
        int $row,
    ): void {
        $smol = new SmolPoW($secret);
        if ($expected_value === 'true') {
            $this->assertTrue(
                $smol->validateString($solution, $challenge_string),
                printf(
                    'Row %s: %s: expected true',
                    $row,
                    $description,
                )
            );
        } elseif ($expected_value === 'false') {
            $this->assertFalse(
                $smol->validateString($solution, $challenge_string),
                printf(
                    'Row %s: %s: expected false',
                    $row,
                    $description,
                )
            );
        } elseif ($expected_value === 'null') {
            $this->assertNull(
                $smol->validateString($solution, $challenge_string),
                printf(
                    'Row %s: %s: expected null',
                    $row,
                    $description,
                )
            );
        } else {
            throw new \Exception('Invalid expected value');
        }
    }

    public static function csvDataProvider(): Generator
    {
        $path = __DIR__ . '/SmolPoWTest_examples.csv';
        $file = fopen($path, 'r');
        $row_num = 1;
        while (($row = fgetcsv($file)) !== false) {
            $row = array_map(trim(...), $row);
            $row[] = $row_num++;
            yield $row;
        }
        fclose($file);
    }
}
