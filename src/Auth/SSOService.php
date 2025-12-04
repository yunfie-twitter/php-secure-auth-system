<?php

namespace App\Auth;

use App\Models\User;
use App\Models\SSOProvider;
use App\Security\JWTService;

class SSOService
{
    private bool $enabled;
    private JWTService $jwtService;

    public function __construct()
    {
        $this->enabled = filter_var($_ENV['SSO_ENABLED'] ?? false, FILTER_VALIDATE_BOOLEAN);
        $this->jwtService = new JWTService();
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function getAuthorizationUrl(string $returnUrl = ''): string
    {
        $providerUrl = $_ENV['SSO_PROVIDER_URL'] ?? '';
        $callbackUrl = $_ENV['SSO_CALLBACK_URL'] ?? '';
        
        $state = bin2hex(random_bytes(16));
        $_SESSION['sso_state'] = $state;
        $_SESSION['sso_return_url'] = $returnUrl;

        $params = http_build_query([
            'client_id' => $_ENV['OIDC_CLIENT_ID'] ?? '',
            'redirect_uri' => $callbackUrl,
            'response_type' => 'code',
            'scope' => 'openid profile email',
            'state' => $state,
        ]);

        return $providerUrl . '/authorize?' . $params;
    }

    public function handleCallback(array $params): array
    {
        if (!$this->enabled) {
            return ['success' => false, 'errors' => ['SSO is not enabled']];
        }

        $state = $params['state'] ?? '';
        $code = $params['code'] ?? '';

        if (!isset($_SESSION['sso_state']) || $state !== $_SESSION['sso_state']) {
            return ['success' => false, 'errors' => ['Invalid state parameter']];
        }

        if (!$code) {
            return ['success' => false, 'errors' => ['Missing authorization code']];
        }

        try {
            $tokenData = $this->exchangeCodeForToken($code);
            $userInfo = $this->getUserInfo($tokenData['access_token']);

            $providerUserId = $userInfo['sub'] ?? $userInfo['id'] ?? null;
            $email = $userInfo['email'] ?? null;
            $name = $userInfo['name'] ?? null;

            if (!$providerUserId) {
                return ['success' => false, 'errors' => ['Invalid user info: missing user ID']];
            }

            $ssoProvider = SSOProvider::findByProvider('sso', $providerUserId);
            
            if ($ssoProvider) {
                $user = User::findById($ssoProvider->user_id);
            } else {
                if (!$email) {
                    return ['success' => false, 'errors' => ['Email is required for registration']];
                }

                $existingUser = User::findByEmail($email);
                
                if ($existingUser) {
                    $user = $existingUser;
                } else {
                    $username = explode('@', $email)[0] ?? 'user_' . bin2hex(random_bytes(4));
                    
                    $user = User::create([
                        'email' => $email,
                        'username' => $username,
                        'password_hash' => password_hash(bin2hex(random_bytes(32)), PASSWORD_BCRYPT),
                        'display_name' => $name ?? $username,
                        'email_verified' => 1,
                    ]);
                }

                SSOProvider::create($user->id, 'sso', $providerUserId, $userInfo);
            }

            $accessToken = $this->jwtService->createAccessToken([
                'sub' => $user->uuid,
                'user_id' => $user->id,
                'email' => $user->email,
                'username' => $user->username,
            ]);

            $refreshToken = $this->jwtService->createRefreshToken([
                'sub' => $user->uuid,
                'user_id' => $user->id,
            ]);

            return [
                'success' => true,
                'access_token' => $accessToken,
                'refresh_token' => $refreshToken,
                'expires_in' => (int)($_ENV['JWT_EXPIRY'] ?? 3600),
                'return_url' => $_SESSION['sso_return_url'] ?? '/',
            ];

        } catch (\Throwable $e) {
            error_log('SSO Callback Error: ' . $e->getMessage());
            return ['success' => false, 'errors' => ['SSO authentication failed: ' . $e->getMessage()]];
        }
    }

    private function exchangeCodeForToken(string $code): array
    {
        $providerUrl = $_ENV['SSO_PROVIDER_URL'] ?? '';
        $callbackUrl = $_ENV['SSO_CALLBACK_URL'] ?? '';
        
        $ch = curl_init($providerUrl . '/token');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $callbackUrl,
            'client_id' => $_ENV['OIDC_CLIENT_ID'] ?? '',
            'client_secret' => $_ENV['OIDC_CLIENT_SECRET'] ?? '',
        ]));

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200) {
            throw new \RuntimeException('Token exchange failed');
        }

        return json_decode($response, true);
    }

    private function getUserInfo(string $accessToken): array
    {
        $providerUrl = $_ENV['SSO_PROVIDER_URL'] ?? '';
        
        $ch = curl_init($providerUrl . '/userinfo');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Bearer ' . $accessToken,
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200) {
            throw new \RuntimeException('UserInfo request failed');
        }

        return json_decode($response, true);
    }
}
