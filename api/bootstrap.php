<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');

$configPath = __DIR__ . '/config.local.php';
if (!is_file($configPath)) {
    http_response_code(503);
    echo json_encode(['error' => 'service_unavailable'], JSON_THROW_ON_ERROR);
    exit;
}

$config = require $configPath;

function api_response(array $payload, int $status = 200): never
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    exit;
}

function db_connection(array $config): PDO
{
    $db = $config['db'];
    $dsn = sprintf(
        'mysql:host=%s;dbname=%s;charset=%s',
        $db['host'],
        $db['name'],
        $db['charset'] ?? 'utf8mb4',
    );

    return new PDO($dsn, $db['user'], $db['password'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
}

function require_api_token(array $config): void
{
    $authorization = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\\s+(.+)$/i', $authorization, $matches)) {
        api_response(['error' => 'unauthorized'], 401);
    }

    $hash = $config['api_token_hash'] ?? '';
    if (!is_string($hash) || $hash === '' || !password_verify($matches[1], $hash)) {
        api_response(['error' => 'unauthorized'], 401);
    }
}

function require_json_request(): void
{
    $contentType = strtolower($_SERVER['CONTENT_TYPE'] ?? '');
    if (!str_starts_with($contentType, 'application/json')) {
        api_response(['error' => 'json_required'], 415);
    }
}

function request_json(int $maxBytes = 524288): array
{
    $length = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($length > $maxBytes) api_response(['error' => 'payload_too_large'], 413);
    $raw = file_get_contents('php://input');
    if ($raw === false || strlen($raw) > $maxBytes) api_response(['error' => 'payload_too_large'], 413);
    try { $data = json_decode($raw, true, 32, JSON_THROW_ON_ERROR); }
    catch (Throwable) { api_response(['error' => 'invalid_json'], 400); }
    if (!is_array($data)) api_response(['error' => 'json_object_required'], 400);
    return $data;
}

function uuid_value(mixed $value, string $field): string
{
    if (!is_string($value) || !preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $value)) {
        api_response(['error' => 'invalid_' . $field], 422);
    }
    return strtolower($value);
}

function sync_context(array $input): array
{
    return [uuid_value($input['account_id'] ?? null, 'account_id'), uuid_value($input['device_id'] ?? null, 'device_id')];
}

function random_uuid(): string
{
    $bytes = random_bytes(16);
    $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
    $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
}

function bearer_token(): string
{
    $authorization = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/i', $authorization, $matches)) api_response(['error' => 'unauthorized'], 401);
    return trim($matches[1]);
}

function authenticate_device(PDO $pdo): array
{
    $token = bearer_token();
    $stmt = $pdo->query('SELECT id, account_id, token_hash FROM devices WHERE revoked_at IS NULL');
    foreach ($stmt->fetchAll() as $device) {
        if (password_verify($token, $device['token_hash'])) {
            return [$device['account_id'], $device['id']];
        }
    }
    api_response(['error' => 'unauthorized'], 401);
}
