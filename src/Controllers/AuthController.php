<?php

namespace App\Controllers;

use App\Auth\AuthService;
use App\Security\CSRFProtection;
use App\Security\XSSProtection;

class AuthController
{
    public function __construct(private AuthService $authService = new AuthService()) {}

    private function jsonResponse(array $data, int $statusCode = 200): void
    {
        http_response_code($statusCode);
        header('Content-Type: application/json; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: SAMEORIGIN');
        header('X-XSS-Protection: 1; mode=block');
        header('Referrer-Policy: no-referrer-when-downgrade');
        header('Content-Security-Policy: default-src \"none\"; frame-ancestors \"none\"; base-uri \"none\"; form-action \"self\"');

        echo json_encode(XSSProtection::sanitizeForJSON($data), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    private function getJsonInput(): array
    {
        $raw = file_get_contents('php://input');
        $data = json_decode($raw, true) ?? [];
        return is_array($data) ? $data : [];
    }

    public function register(): void
    {
        $input = $get = $_GET ?? [];
        $headers = getallheaders();
        $csrfToken = $headers['X-CSRF-Token'] ?? $headers['X-Csrf-Token'] ?? null;

        if (!CSRFProtection::validateToken($csrfToken)) {
            $this->jsonResponse(['success' => false, 'errors' => ['CSRFトークンが無効です']], 400);
            return;
        }

        $input = $this->getJsonInput();
        $result = $this->authService->register($input);
        $this->jsonResponse($result, $result['success'] ? 201 : 400);
    }

    public function login(): void
    {
        $headers = getallheaders();
        $csrfToken = $headers['X-CSRF-Token'] ?? $headers['X-Csrf-Token'] ?? null;

        if (!CSRFProtection::validateToken($csrfToken)) {
            $this->jsonResponse(['success' => false, 'errors' => ['CSRFトークンが無効です']], 400);
            return;
        }

        $input = $this->getJsonInput();
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

        $result = $this->authService->login($input, $ip, $userAgent);
        $this->jsonResponse($result, $result['success'] ? 200 : 401);
    }

    public function me(): void
    {
        $headers = getallheaders();
        $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';

        $result = $this->authService->me($authHeader);
        $this->jsonResponse($result, $result['success'] ? 200 : 401);
    }
}
