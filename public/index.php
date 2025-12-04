<?php

require __DIR__ . '/../vendor/autoload.php';

use App\Controllers\AuthController;
use App\Security\CSRFProtection;
use Dotenv\Dotenv;

$dotenv = Dotenv::createImmutable(__DIR__ . '/..');
$dotenv->load();

if (session_status() === PHP_SESSION_NONE) {
    session_start([
        'cookie_httponly' => true,
        'cookie_secure' => isset($_SERVER['HTTPS']),
        'cookie_samesite' => 'Lax',
    ]);
}

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

$authController = new AuthController();

if ($uri === '/api/auth/csrf-token' && $method === 'GET') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['csrf_token' => CSRFProtection::generateToken()]);
    exit;
}

if ($uri === '/api/auth/register' && $method === 'POST') {
    $authController->register();
    exit;
}

if ($uri === '/api/auth/login' && $method === 'POST') {
    $authController->login();
    exit;
}

if ($uri === '/api/auth/me' && $method === 'GET') {
    $authController->me();
    exit;
}

http_response_code(404);
header('Content-Type: application/json; charset=utf-8');
echo json_encode(['success' => false, 'error' => 'Not Found']);
