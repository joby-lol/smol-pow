<script src="smolpow.js"></script>
<?php

use Joby\Smol\PoW\SmolPoW;

include __DIR__ . '/vendor/autoload.php';

$algos = ['sha256'];
$difficulties = [1, 2, 3, 4, 5];
$times = [1000, PHP_INT_MAX];
$secrets = ['super_secret_123'];

$invalid_rows = [];

foreach ($algos as $algo) {
    foreach ($difficulties as $difficulty) {
        foreach ($times as $time) {
            foreach ($secrets as $secret) {
                $pow = new SmolPoW($secret, $algo, $difficulty, allowed_algorithms: $algos);
                $challenge = $pow->challenge('/safe_return/', $time);
                $challenge_string = encodeString($challenge);
                $challenge_id = 'ch_' . md5($challenge_string);
                $expired = time() > $time;
                $expected_return = $expired ? 'null' : 'true';
                printf(
                    '<div id="%s">%s, valid %s, %s, %d, %d, %s, %s, </div>',
                    $challenge_id,
                    $expected_return,
                    $expired ? 'expired' : 'not expired',
                    $algo,
                    $difficulty,
                    $time,
                    $secret,
                    $challenge_string
                );
                printf('<script>smolPoW.run({hash:"%s", ignoreExpiration:true, onSolve:function(s){document.getElementById("%s").innerHTML += s;}, onStatus: function(s){console.log(s);}, onError: function(e){console.log(e.message);}});</script>', $challenge_string, $challenge_id);
                // generate invalid version with wrong solution
                $invalid_rows[] = sprintf(
                    '<div>%s, invalid solution %s, %s, %d, %d, %s, %s, abcdefgh</div>',
                    $expired ? 'null' : 'false',
                    $expired ? 'expired' : 'not expired',
                    $algo,
                    $difficulty,
                    $time,
                    $secret,
                    $challenge_string
                );
                // generate invalid version by making algorithm an int
                $invalid = $challenge;
                $invalid[0] = 2;
                $invalid_string = encodeString($invalid);
                $invalid_rows[] = sprintf('<div>false, invalid algorithm %s, %s, %d, %d, %s, %s, </div>', $expired ? 'expired' : 'not expired', $algo, $difficulty, $time, $secret, $invalid_string);
                // generate invalid version by making algorithm something unsupported
                $invalid = $challenge;
                $invalid[0] = 'sha1';
                $invalid_string = encodeString($invalid);
                $invalid_rows[] = sprintf('<div>false, disallowed algorithm %s, %s, %d, %d, %s, %s, </div>', $expired ? 'expired' : 'not expired', $algo, $difficulty, $time, $secret, $invalid_string);
                // generate invalid version by making up an algorithm
                $invalid = $challenge;
                $invalid[0] = 'smolpow2';
                $invalid_string = encodeString($invalid);
                $invalid_rows[] = sprintf('<div>false, non-existent algorithm %s, %s, %d, %d, %s, %s, </div>', $expired ? 'expired' : 'not expired', $algo, $difficulty, $time, $secret, $invalid_string);
                // generate invalid version by making nonce an integer
                $invalid = $challenge;
                $invalid[1] = 2;
                $invalid_string = encodeString($invalid);
                $invalid_rows[] = sprintf('<div>false, invalid nonce %s, %s, %d, %d, %s, %s, </div>', $expired ? 'expired' : 'not expired', $algo, $difficulty, $time, $secret, $invalid_string);
                // generate invalid version by tampering with nonce
                $invalid = $challenge;
                $invalid[1] = bin2hex(random_bytes(32));
                $invalid_string = encodeString($invalid);
                $invalid_rows[] = sprintf('<div>false, tampered nonce %s, %s, %d, %d, %s, %s, </div>', $expired ? 'expired' : 'not expired', $algo, $difficulty, $time, $secret, $invalid_string);
                // generate invalid version by making difficulty a string
                $invalid = $challenge;
                $invalid[2] = "2";
                $invalid_string = encodeString($invalid);
                $invalid_rows[] = sprintf('<div>false, invalid difficulty %s, %s, %d, %d, %s, %s, </div>', $expired ? 'expired' : 'not expired', $algo, $difficulty, $time, $secret, $invalid_string);
                // generate invalid version by making difficulty negative
                $invalid = $challenge;
                $invalid[2] = -1;
                $invalid_string = encodeString($invalid);
                $invalid_rows[] = sprintf('<div>false, negative difficulty %s, %s, %d, %d, %s, %s, </div>', $expired ? 'expired' : 'not expired', $algo, $difficulty, $time, $secret, $invalid_string);
                // generate invalid version by tampering with difficulty
                $invalid = $challenge;
                $invalid[2] += 1;
                $invalid_string = encodeString($invalid);
                $invalid_rows[] = sprintf('<div>false, tampered difficulty %s, %s, %d, %d, %s, %s, </div>', $expired ? 'expired' : 'not expired', $algo, $difficulty, $time, $secret, $invalid_string);
                // generate invalid version by making expiry a string
                $invalid = $challenge;
                $invalid[3] = strval($invalid[3]);
                $invalid_string = encodeString($invalid);
                $invalid_rows[] = sprintf('<div>false, string expiry %s, %s, %d, %d, %s, %s, </div>', $expired ? 'expired' : 'not expired', $algo, $difficulty, $time, $secret, $invalid_string);
                // generate invalid version by tampering with expiry
                $invalid = $challenge;
                $invalid[3] += 1;
                $invalid_string = encodeString($invalid);
                $invalid_rows[] = sprintf('<div>false, tampered expiry %s, %s, %d, %d, %s, %s, </div>', $expired ? 'expired' : 'not expired', $algo, $difficulty, $time, $secret, $invalid_string);
                // generate invalid version by making return URL an integer
                $invalid = $challenge;
                $invalid[4] = 2;
                $invalid_string = encodeString($invalid);
                $invalid_rows[] = sprintf('<div>false, integer return URL %s, %s, %d, %d, %s, %s, </div>', $expired ? 'expired' : 'not expired', $algo, $difficulty, $time, $secret, $invalid_string);
                // generate invalid version by tampering with return URL
                $invalid = $challenge;
                $invalid[4] = "/evil-return-url/";
                $invalid_string = encodeString($invalid);
                $invalid_rows[] = sprintf('<div>false, tampered return URL %s, %s, %d, %d, %s, %s, </div>', $expired ? 'expired' : 'not expired', $algo, $difficulty, $time, $secret, $invalid_string);
                // generate invalid version by making HMAC an integer
                $invalid = $challenge;
                $invalid[5] = 2;
                $invalid_string = encodeString($invalid);
                $invalid_rows[] = sprintf('<div>false, integer HMAC %s, %s, %d, %d, %s, %s, </div>', $expired ? 'expired' : 'not expired', $algo, $difficulty, $time, $secret, $invalid_string);
                // generate invalid version by tampering with HMAC
                $invalid = $challenge;
                $invalid[5] = bin2hex(random_bytes(32));
                $invalid_string = encodeString($invalid);
                $invalid_rows[] = sprintf('<div>false, tampered HMAC %s, %s, %d, %d, %s, %s, </div>', $expired ? 'expired' : 'not expired', $algo, $difficulty, $time, $secret, $invalid_string);
            }
        }
    }
}

foreach ($invalid_rows as $invalid_row) {
    echo $invalid_row;
}

function encodeString(array $challenge): string
{
    return base64_encode(json_encode($challenge, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
}
