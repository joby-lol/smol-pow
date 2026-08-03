# smolPoW

A simple and stateless proof of work system using HMAC and designed to allow developers to drop in PoW to existing web applications with minimal friction. The main purpose is to allow an entirely static HTML/JS page to do a simple PoW and then bounce back to the specified URL.

## Installation

```bash
composer require joby-lol/smol-query
```

## Challenge structure

Each challenge can be passed from the server to the verification page as a single string. It is designed to be put in the URL hash, so that client-side JS can access it but it will not appear in most traffic logs.

Each challenge string is a base64-encoded JSON array with the following fields (in order):
- algorithm name (string)
- challenge nonce (random string)
- difficulty (integer)
- expiry timestamp (integer)
- return URL (string)
- HMAC signature of the above fields using the given algorithm and a server-supplied secret key (string)

Once solved, the solution can be sent back to the server to be verified by setting a cookie named `smolpow` containing the solution and the original challenge string, separated by a pipe character, and redirecting the client back to the return URL.

## PoW algorithm

The proof of work algorithm itself is very simple: generate a string which, when appended to the given challenge nonce and hashed using SHA-256, results in a hash which starts with a certain number of zero bits (specified by the difficulty value). This can be done in a few different ways, but the basic idea is to try different strings until a valid one is found. Solutions are required to be at least 8 characters long but less than 32 characters long.

## Implementation

To use smolPoW in your application, you need to:

1. On any page that should be inaccessible for a bot, generate a challenge according to the above format.
2. Redirect to a page on the same domain as the return URL using the challenge as a URL fragment.
3. Include smolpow.js in that page and call smolPoW.run() on page load.
4. On success, smolPoW will set a cookie containing the solution and the original challenge string, separated by a pipe character, and redirect the client back to the return URL.
5. On failure, smolPoW will display an error message and you should likely provide a way to retry. Do not redirect on failure.
6. On the target page, you must verify the solution contained in the cookie and that the challenge is valid before completing the requested action.

## Requirements

Fully tested on PHP 8.3+, static analysis for PHP 8.1+. No external dependencies.

## License

MIT License - See [LICENSE](LICENSE) file for details.