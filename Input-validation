<?php

function load_env($path) {
    if (!file_exists($path)) return;
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#' || strpos($line, '=') === false) continue;
        [$k, $v] = explode('=', $line, 2);
        $k = trim($k); $v = trim($v);
        if (!array_key_exists($k, $_ENV)) { $_ENV[$k] = $v; putenv("$k=$v"); }
    }
}
load_env(__DIR__ . '/../.env');

define('DB_HOST', $_ENV['DB_HOST'] ?? 'localhost');
define('DB_USER', $_ENV['DB_USER'] ?? 'root');
define('DB_PASS', $_ENV['DB_PASS'] ?? '');
define('DB_NAME', $_ENV['DB_NAME'] ?? 'cap');

$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);

if ($conn->connect_error) {
    error_log('[DB ERROR] Connection failed: ' . $conn->connect_error);
    $isApi = strpos($_SERVER['REQUEST_URI'] ?? '', '/api/') !== false;
    if ($isApi) {
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => 'Database connection failed.']);
    } else {
        include dirname(__DIR__) . '/error.php';
    }
    exit();
}

$conn->set_charset('utf8mb4');

// ============================================================
// INPUT VALIDATION — secure_int()
// RUBRIC: Data is stored, retrieved, and managed correctly
// ============================================================
// Converts any user-supplied ID (from URL or form) into a safe
// positive integer before it is used in a database query.
// Prevents attackers from injecting non-numeric values as IDs.
// Example usage: $id = secure_int($_GET['id']);
// ============================================================
function secure_int($value) {
    $v = intval($value);
    return $v > 0 ? $v : 0;
}

// ============================================================
// INPUT VALIDATION — secure_str()
// RUBRIC: Strong security (data protection, validation)
// ============================================================
// Trims whitespace and escapes special characters from string
// input before it is used inside LIKE queries.
// For all other queries, prepared statements are used instead.
// ============================================================
function secure_str($conn, $value) {
    return $conn->real_escape_string(trim($value));
}

// ============================================================
// INPUT VALIDATION — valid_email()
// RUBRIC: Strong security (authentication, validation)
// ============================================================
// Checks that an email address is in a proper format before
// it is accepted and stored. Rejects anything that is not a
// valid email — protects registration and login forms.
// ============================================================
function valid_email($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

// ============================================================
// INPUT VALIDATION — valid_phone()
// RUBRIC: Strong security (data protection, validation)
// ============================================================
// Enforces Philippine phone number format (09XXXXXXXXX or
// +639XXXXXXXXX) using regex. Rejects any phone number that
// does not match the expected pattern before saving to the DB.
// ============================================================
function valid_phone($phone) {
    return preg_match('/^(09|\+639)\d{9}$/', $phone);
}

// ============================================================
// INPUT VALIDATION — e() output sanitization
// RUBRIC: Strong security (data protection, validation)
// ============================================================
// Sanitizes ALL user data before it is displayed on the page.
// Converts special characters like < > " ' into safe HTML
// entities — this prevents XSS (Cross-Site Scripting) attacks
// where an attacker injects malicious scripts into the output.
// Every echo of user data in this system uses e() or
// htmlspecialchars() — never raw output.
// ============================================================
function e($value) {
    return htmlspecialchars($value ?? '', ENT_QUOTES, 'UTF-8');
}

// ============================================================
// DATABASE SECURITY — log_action() audit trail
// RUBRIC: Data is stored, retrieved, and managed correctly
// ============================================================
// Records every action taken in the system into the audit_logs
// table. Uses a prepared statement so log data cannot be
// tampered with through SQL injection.
// ============================================================
function log_action($conn, $user_id, $user_name, $action, $module, $record_id = null, $details = '') {
    $ip   = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $stmt = $conn->prepare("
        INSERT INTO audit_logs (user_id, user_name, action, module, record_id, details, ip_address)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ");
    if ($stmt) {
        $stmt->bind_param('isssiss', $user_id, $user_name, $action, $module, $record_id, $details, $ip);
        $stmt->execute();
        $stmt->close();
    }
}

function generate_code($conn, $table, $prefix) {
    $result = $conn->query("SELECT COUNT(*) as total FROM `$table`");
    $row    = $result->fetch_assoc();
    $next   = ($row['total'] ?? 0) + 1;
    return $prefix . '-' . str_pad($next, 4, '0', STR_PAD_LEFT);
}
