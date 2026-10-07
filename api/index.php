<?php
declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

$route = $_GET['route'] ?? trim(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH), '/');

if ($route === '' || $route === 'health') {
    try {
        $pdo = db_connection($config);
        $pdo->query('SELECT 1');
        api_response(['status' => 'ok']);
    } catch (Throwable) {
        api_response(['error' => 'service_unavailable'], 503);
    }
}

if ($route === 'private-health') {
    require_api_token($config);
    api_response(['status' => 'ok']);
}

if (str_starts_with($route, 'sync/')) {
    require_json_request();
    $pdo = db_connection($config);
    $input = request_json();
    [$accountId, $deviceId] = authenticate_device($pdo);
    if (isset($input['account_id'], $input['device_id'])) {
        [$requestedAccount, $requestedDevice] = sync_context($input);
        if ($requestedAccount !== $accountId || $requestedDevice !== $deviceId) api_response(['error' => 'device_not_authorized'], 403);
    }
    $device = $pdo->prepare('SELECT id FROM devices WHERE id = ? AND account_id = ? AND revoked_at IS NULL');
    $device->execute([$deviceId, $accountId]);
    if (!$device->fetch()) api_response(['error' => 'device_not_authorized'], 403);

    if ($route === 'sync/push') {
        if (!is_array($input['records'] ?? null) || count($input['records']) > 100) api_response(['error' => 'invalid_records'], 422);
        $pdo->beginTransaction();
        try {
            $stmt = $pdo->prepare('INSERT INTO encrypted_records (account_id, record_id, record_type, ciphertext, record_version, deleted_at) VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE ciphertext = VALUES(ciphertext), record_type = VALUES(record_type), record_version = VALUES(record_version), deleted_at = VALUES(deleted_at)');
            foreach ($input['records'] as $record) {
                if (!is_array($record) || !is_string($record['record_id'] ?? null) || strlen($record['record_id']) > 160 || !is_string($record['record_type'] ?? null) || strlen($record['record_type']) > 80 || !is_string($record['ciphertext'] ?? null) || strlen($record['ciphertext']) > 400000 || !is_int($record['record_version'] ?? null) || $record['record_version'] < 1) api_response(['error' => 'invalid_record'], 422);
                $stmt->execute([$accountId, $record['record_id'], $record['record_type'], $record['ciphertext'], $record['record_version'], !empty($record['deleted']) ? date('Y-m-d H:i:s') : null]);
            }
            $pdo->commit();
            api_response(['status' => 'ok', 'accepted' => count($input['records'])]);
        } catch (Throwable) { $pdo->rollBack(); api_response(['error' => 'sync_failed'], 500); }
    }
    if ($route === 'sync/pull') {
        $after = max(0, (int) ($input['after'] ?? 0));
        $stmt = $pdo->prepare('SELECT record_id, record_type, ciphertext, record_version, deleted_at FROM encrypted_records WHERE account_id = ? AND record_version > ? ORDER BY record_version ASC LIMIT 100');
        $stmt->execute([$accountId, $after]);
        api_response(['status' => 'ok', 'records' => $stmt->fetchAll()]);
    }
    if ($route === 'sync/delete') {
        $recordId = $input['record_id'] ?? null;
        if (!is_string($recordId) || $recordId === '' || strlen($recordId) > 160) api_response(['error' => 'invalid_record_id'], 422);
        $stmt = $pdo->prepare('UPDATE encrypted_records SET deleted_at = CURRENT_TIMESTAMP WHERE account_id = ? AND record_id = ?');
        $stmt->execute([$accountId, $recordId]);
        api_response(['status' => 'ok']);
    }
}

if ($route === 'provision') {
    require_api_token($config);
    require_json_request();
    $input = request_json(8192);
    $label = $input['label'] ?? '';
    if (!is_string($label) || trim($label) === '' || strlen($label) > 120) api_response(['error' => 'invalid_label'], 422);
    $pdo = db_connection($config);
    $accountId = random_uuid();
    $deviceId = random_uuid();
    $deviceToken = bin2hex(random_bytes(32));
    $pdo->beginTransaction();
    try {
        $pdo->prepare('INSERT INTO accounts (id) VALUES (?)')->execute([$accountId]);
        $pdo->prepare('INSERT INTO devices (id, account_id, label, token_hash) VALUES (?, ?, ?, ?)')->execute([$deviceId, $accountId, trim($label), password_hash($deviceToken, PASSWORD_DEFAULT)]);
        $pdo->commit();
        api_response(['status' => 'ok', 'account_id' => $accountId, 'device_id' => $deviceId, 'device_token' => $deviceToken], 201);
    } catch (Throwable) { $pdo->rollBack(); api_response(['error' => 'provision_failed'], 500); }
}

api_response(['error' => 'not_found'], 404);
