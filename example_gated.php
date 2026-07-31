<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8" />
    <title>SmolPoW example gated page</title>
</head>

<body>
    <h1>SmolPoW example gated page</h1>

    <p>This page demonstrates the flow between a PHP page requesting proof of work from a javascript solver, and that javascript page solving it and setting a cookie. Then, a PHP script can validate that cookie to determine whether or not to show the user the content.</p>

    <?php

    use Joby\Smol\PoW\SmolPoW;

    include __DIR__ . '/vendor/autoload.php';

    $pow = new SmolPoW('secret_token');

    $cookie_value = @$_COOKIE['smolpow'];
    $cookie_validation = false;

    if ($cookie_value) {
        echo '<h2>Cookie value</h2>';
        $start = microtime(true);
        $cookie_validation = $pow->validateCookieValue($cookie_value);
        $time = microtime(true) - $start;
        printf('<p><strong>value:</strong> <kbd>%s</kbd></p>', htmlentities($cookie_value));
        if ($cookie_validation === true)
            printf('<p><strong>valid (validation took %f seconds)</strong></p>', $time);
        else if ($cookie_validation === false)
            printf('<p><strong>invalid (validation took %f seconds)</strong></p>', $time);
        else
            printf('<p><strong>expired (validation took %f seconds)</strong></p>', $time);
    }

    if ($cookie_validation === true) {
        echo '<h2>Gated content</h2>';
        echo '<p>If you can see this, you have solved the proof of work!</p>';
    } else {
        echo '<h2 style="color: #999;">Gated content</h2>';
        echo '<p style="color: #999;">You have not solved the proof of work. Click the link below to solve it and view this content.</p>';
    }

    echo '<h2>New challenge</h2>';
    $start = microtime(true);
    $challenge_string = $pow->challengeString($_SERVER['REQUEST_URI']);
    $time = microtime(true) - $start;
    printf('<p><strong>String (generation took %f seconds):</strong> <kbd>%s</kbd></p>', $time, htmlentities($challenge_string));
    printf('<p><a href="/example_solver.html#%s">Click here to run solver</a></p>', htmlentities($challenge_string));
    ?>
</body>

</html>