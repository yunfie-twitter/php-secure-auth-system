<?php

namespace App\Controllers;

use App\Auth\AuthService;
use App\Auth\OIDCService;
use App\Auth\SSOService;
use App\Security\CSRFProtection;
use App\Security\XSSProtection;

class AuthController
{
    public function __construct(
        private AuthService $authService = new AuthService(),
        private OIDCService $oidcService = new OIDCService(),
        private SSOService $ssoService = new SSOService()
    ) {}

    private function jsonResponse(array $data, int $statusCode = 200): void
    {
        http_response_code($statusCode);
        header('Content-Type: application/json; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: SAMEORIGIN');
        header('X-XSS-Protection: 1; mode=block');
        header('Referrer-Policy: no-referrer-when-downgrade');
        header('Content-Security-Policy: default-src \'none\'; frame-ancestors \'none\'; base-uri \'none\'; form-action \'self\'');

        echo json_encode(XSSProtection::sanitizeForJSON($data), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    private function getJsonInput(): array
    {
        $raw = file_get_contents('php://input');
        $data = json_decode($raw, true) ?? [];
        return is_array($data) ? $data : [];
    }

    private function validateCSRF(): bool
    {
        $headers = getallheaders();
        $csrfToken = $headers['X-CSRF-Token'] ?? $headers['X-Csrf-Token'] ?? null;
        return CSRFProtection::validateToken($csrfToken);
    }

    public function register(): void
    {
        if (!$this->validateCSRF()) {
            $this->jsonResponse(['success' => false, 'errors' => ['CSRFトークンが無効です']], 400);
            return;
        }

        $input = $this->getJsonInput();
        $result = $this->authService->register($input);
        $this->jsonResponse($result, $result['success'] ? 201 : 400);
    }

    public function login(): void
    {
        if (!$this->validateCSRF()) {
            $this->jsonResponse(['success' => false, 'errors' => ['CSRFトークンが無効です']], 400);
            return;
        }

        $input = $this->getJsonInput();
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

        $result = $this->authService->login($input, $ip, $userAgent);
        $this->jsonResponse($result, $result['success'] ? 200 : 401);
    }

    public function refresh(): void
    {
        $input = $this->getJsonInput();
        $refreshToken = $input['refresh_token'] ?? '';

        if (!$refreshToken) {
            $this->jsonResponse(['success' => false, 'errors' => ['リフレッシュトークンが必要です']], 400);
            return;
        }

        $result = $this->authService->refresh($refreshToken);
        $this->jsonResponse($result, $result['success'] ? 200 : 401);
    }

    public function logout(): void
    {
        $headers = getallheaders();
        $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';
        
        $input = $this->getJsonInput();
        $refreshToken = $input['refresh_token'] ?? null;

        $result = $this->authService->logout($authHeader, $refreshToken);
        $this->jsonResponse($result, 200);
    }

    public function me(): void
    {
        $headers = getallheaders();
        $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';

        $result = $this->authService->me($authHeader);
        $this->jsonResponse($result, $result['success'] ? 200 : 401);
    }

    public function oidcLogin(): void
    {
        if (!$this->oidcService->isEnabled()) {
            $this->jsonResponse(['success' => false, 'errors' => ['OpenID Connect is not enabled']], 400);
            return;
        }

        $this->oidcService->getAuthorizationUrl();
    }

    public function oidcCallback(): void
    {
        if (!$this->oidcService->isEnabled()) {
            $this->jsonResponse(['success' => false, 'errors' => ['OpenID Connect is not enabled']], 400);
            return;
        }

        $result = $this->oidcService->handleCallback();
        $this->jsonResponse($result, $result['success'] ? 200 : 401);
    }

    public function ssoLogin(): void
    {
        if (!$this->ssoService->isEnabled()) {
            $this->jsonResponse(['success' => false, 'errors' => ['SSO is not enabled']], 400);
            return;
        }

        $returnUrl = $_GET['return_url'] ?? '/';
        $authUrl = $this->ssoService->getAuthorizationUrl($returnUrl);
        
        header('Location: ' . $authUrl);
        exit;
    }

    public function ssoCallback(): void
    {
        if (!$this->ssoService->isEnabled()) {
            $this->jsonResponse(['success' => false, 'errors' => ['SSO is not enabled']], 400);
            return;
        }

        $result = $this->ssoService->handleCallback($_GET);
        
        if ($result['success'] && isset($result['return_url'])) {
            $returnUrl = $result['return_url'];
            $token = $result['access_token'];
            header('Location: ' . $returnUrl . '?token=' . urlencode($token));
            exit;
        }

        $this->jsonResponse($result, $result['success'] ? 200 : 401);
    }
}
