<?php
declare(strict_types=1);

return [
    'db' => [
        'host' => 'localhost',
        'name' => 'direnz37_calc',
        'user' => 'direnz37_3direnzo',
        'password' => 'CHANGE_ME_ON_SERVER',
        'charset' => 'utf8mb4',
    ],
    'cors_origins' => [
        'https://calc.3direnzo.com.br',
    ],
    // Generate with: php -r 'echo password_hash(bin2hex(random_bytes(32)), PASSWORD_DEFAULT), PHP_EOL;'
    // Keep the plain token only in the client secret store, never in this file.
    'api_token_hash' => 'REPLACE_WITH_PASSWORD_HASH',
];
