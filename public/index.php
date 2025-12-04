<?php

require __DIR__ . '/../vendor/autoload.php';

use App\Controllers\AuthController;
use App\Security\CSRFProtection;
use App\Models\RefreshToken;
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

if (rand(1, 10) === 1) {
    RefreshToken::cleanupExpired();
}

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

$allowedOrigins = explode(',', $_ENV['CORS_ALLOWED_ORIGINS'] ?? 'http://localhost');
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

if (in_array($origin, $allowedOrigins)) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Access-Control-Allow-Credentials: true');
}

if ($method === 'OPTIONS') {
    header('Access-Control-Allow-Methods: ' . ($_ENV['CORS_ALLOWED_METHODS'] ?? 'GET,POST,PUT,DELETE,OPTIONS'));
    header('Access-Control-Allow-Headers: ' . ($_ENV['CORS_ALLOWED_HEADERS'] ?? 'Content-Type,Authorization,X-CSRF-Token'));
    header('Access-Control-Max-Age: ' . ($_ENV['CORS_MAX_AGE'] ?? '3600'));
    http_response_code(204);
    exit;
}

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

if ($uri === '/api/auth/verify-email' && $method === 'GET') {
    $authController->verifyEmail();
    exit;
}

if ($uri === '/api/auth/resend-verification' && $method === 'POST') {
    $authController->resendVerification();
    exit;
}

if ($uri === '/api/auth/login' && $method === 'POST') {
    $authController->login();
    exit;
}

if ($uri === '/api/auth/refresh' && $method === 'POST') {
    $authController->refresh();
    exit;
}

if ($uri === '/api/auth/logout' && $method === 'POST') {
    $authController->logout();
    exit;
}

if ($uri === '/api/auth/me' && $method === 'GET') {
    $authController->me();
    exit;
}

if ($uri === '/api/auth/oidc/login' && $method === 'GET') {
    $authController->oidcLogin();
    exit;
}

if ($uri === '/api/auth/oidc/callback' && $method === 'GET') {
    $authController->oidcCallback();
    exit;
}

if ($uri === '/api/auth/sso/login' && $method === 'GET') {
    $authController->ssoLogin();
    exit;
}

if ($uri === '/api/auth/sso/callback' && $method === 'GET') {
    $authController->ssoCallback();
    exit;
}

http_response_code(404);
header('Content-Type: application/json; charset=utf-8');
echo json_encode(['success' => false, 'error' => 'Not Found']);
