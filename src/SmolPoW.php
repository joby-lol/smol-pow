<?php

/**
 * smolPoW
 * https://github.com/joby-lol/smol-pow
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\PoW;

use InvalidArgumentException;

class SmolPoW
{
    /**
     * Create a new SmolPoW instance.
     * 
     * @param string $secret The secret key used for HMAC signing and proof of work.
     * @param string $hmac_algorithm The HMAC algorithm to use. Must be available on this system and in the allowed algorithms.
     * @param int $difficulty The difficulty of the proof of work. Higher values are harder to solve but will force visitors to wait longer.
     * @param int $expiration The expiration time of the proof of work in seconds. Defaults to 24 hours.
     * @param array<string> $allowed_algorithms An array of allowed HMAC algorithms. Defaults to ['sha256', 'sha512', 'sha3-256', 'sha3-512'].
     */
    public function __construct(
        protected readonly string $secret,
        protected readonly string $hmac_algorithm = 'sha256',
        protected readonly int $difficulty = 5,
        protected readonly int $expiration = 86400,
        protected readonly array $allowed_algorithms = ['sha256']
    ) {
        if (!in_array($this->hmac_algorithm, $this->allowed_algorithms))
            throw new InvalidArgumentException("The hash algorithm \"{$this->hmac_algorithm}\" is not allowed");
        if (!in_array($this->hmac_algorithm, hash_hmac_algos()))
            throw new InvalidArgumentException("The hash algorithm \"{$this->hmac_algorithm}\" is not available on this system");
    }

    /**
     * Get the JavaScript required to execute client-side proof of work challenge solving.
     * 
     * @return string the raw javascript from the current version of the library
     * 
     * @codeCoverageIgnore not worth testing
     */
    public static function javascript(): string
    {
        // @phpstan-ignore-next-line this file is always present and readable
        return file_get_contents(__DIR__ . '/../smolpow.js');
    }

    /**
     * Get a freshly-generated challenge as a base64-encoded string that can be passed to a static solver page in the URL hash. The solver page will run the proof of work and redirect back to the given URL after setting a cookie containing the solution and the challenge string.
     */
    public function challengeString(string $return_url, int|null $expiration = null): string
    {
        return base64_encode(
            json_encode(
                $this->challenge($return_url, $expiration),
                JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
            )
        );
    }

    /**
     * Validate a cookie value (the solution and challenge string, separated by a pipe). Returns true if valid, false if invalid, null if expired. Throws on malformed input.
     */
    public function validateCookieValue(string $cookie_value): bool|null
    {
        $cookie_value = explode('|', $cookie_value);
        if (count($cookie_value) !== 2)
            return false;
        return $this->validateString($cookie_value[0], $cookie_value[1]);
    }

    /**
     * Create a new challenge. This is the array that will be passed to the verification page.
     * 
     * @param string $return_url The URL to redirect to after the proof of work is solved. The solver will check that it is on the same domain.
     * @param int|null $expiration Optional. If null the default will be generated, otherwise provide your own full timestamp for when this challenge should expire.
     * 
     * @return array{0: string, 1: string, 2: int, 3: int, 4: string, 5: string} The algorithm used for the HMAC, the nonce, the difficulty, the expiry time, the return URL, and the HMAC signature.
     * 
     * @internal Generally this should not be used externally, as you can pass the output of challengeString() to the client.
     */
    public function challenge(string $return_url, int|null $expiration = null): array
    {
        $challenge = [
            $this->hmac_algorithm,
            bin2hex(random_bytes(32)),
            $this->difficulty,
            $expiration ?? (time() + $this->expiration),
            $return_url,
        ];
        $challenge[] = hash_hmac(
            $this->hmac_algorithm,
            json_encode($challenge, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
            $this->secret
        );
        return $challenge;
    }

    /**
     * Validate a challenge string and solution. True indicates that it is valid, false indicates that it is invalid, null indicates that it is expired.
     * 
     * @internal Generally this should not be used externally, as you can pass cookie data directly to validateCookieValue() instead.
     */
    public function validateString(string $solution, string $challenge_string): bool|null
    {
        $challenge_array = base64_decode($challenge_string, true);
        if ($challenge_array === false)
            return false;
        $challenge_array = json_decode($challenge_array, true);
        if ($challenge_array === null)
            return false;
        if (!is_array($challenge_array) || count($challenge_array) !== 6)
            return false;
        // @phpstan-ignore-next-line validate() checks the array structure properly
        return $this->validate($solution, $challenge_array);
    }

    /**
     * Attempt to validate a challenge array and solution. True indicates that it is valid, false indicates that it is invalid, null indicates that it is expired.
     * 
     * @param string $solution The solution to the proof of work.
     * @param array{0: string, 1: string, 2: int, 3: int, 4: string, 5: string} $challenge_array The algorithm used for the HMAC, the nonce, the difficulty, the expiry time, the return URL, and the HMAC signature.
     * 
     * @internal Generally this should not be used externally, as you can pass cookie data directly to validateCookieValue() instead.
     */
    public function validate(string $solution, array $challenge_array): bool|null
    {
        // ensure solution is at least long enough to not be brute forced instantly
        if (strlen($solution) < 8)
            return false;
        if (strlen($solution) > 32)
            return false;
        // check each value is the right type
        if (!is_string($challenge_array[0])) // @phpstan-ignore-line we need to double check it
            return false;
        if (!is_string($challenge_array[1])) // @phpstan-ignore-line we need to double check it
            return false;
        if (!is_int($challenge_array[2])) // @phpstan-ignore-line we need to double check it
            return false;
        if ($challenge_array[2] < 1)
            return false;
        if (!is_int($challenge_array[3])) // @phpstan-ignore-line we need to double check it
            return false;
        if (!is_string($challenge_array[4])) // @phpstan-ignore-line we need to double check it
            return false;
        if (!is_string($challenge_array[5])) // @phpstan-ignore-line we need to double check it
            return false;
        // validate time first
        if (time() > $challenge_array[3])
            return null;
        // check that the hash algorithm is allowed
        if (!in_array($challenge_array[0], $this->allowed_algorithms))
            return false;
        // check that hash algorithm is available
        if (!in_array($challenge_array[0], hash_hmac_algos()))
            return false;
        // validate hash
        $hash = array_pop($challenge_array);
        if (!is_string($hash))
            return false;
        $recalculated = hash_hmac(
            $challenge_array[0],
            json_encode($challenge_array, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
            $this->secret
        );
        if (!hash_equals($hash, $recalculated))
            return false;
        // check proof of work solution
        $hashed = hash($challenge_array[0], $challenge_array[1] . $solution, false);
        // check that the number of leading zero bits is greater than or equal to the difficulty
        $prefix = str_repeat('0', $challenge_array[2]);
        return str_starts_with($hashed, $prefix);
    }
}
