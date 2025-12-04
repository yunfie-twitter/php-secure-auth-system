<?php

namespace App\Auth;

use App\Models\User;
use App\Models\RefreshToken;
use App\Security\PasswordValidator;
use App\Security\RateLimiter;
use App\Security\JWTService;
use App\Security\XSSProtection;
use App\Security\CSRFProtection;

class AuthService
{
    public function __construct(
        private PasswordValidator $passwordValidator = new PasswordValidator(),
        private RateLimiter $rateLimiter = new RateLimiter(),
        private JWTService $jwtService = new JWTService()
    ) {}

    public function register(array $input): array
    {
        $email = XSSProtection::sanitizeInput($input['email'] ?? '');
        $username = XSSProtection::sanitizeInput($input['username'] ?? '');
        $password = $input['password'] ?? '';
        $displayName = XSSProtection::sanitizeInput($input['display_name'] ?? '');

        if (!XSSProtection::validateEmail($email)) {
            return ['success' => false, 'errors' => ['メールアドレスの形式が正しくありません']];
        }

        $validation = $this->passwordValidator->validate($password);
        if (!$validation['valid']) {
            return ['success' => false, 'errors' => $validation['errors']];
        }

        if (User::findByEmail($email)) {
            return ['success' => false, 'errors' => ['このメールアドレスは既に登録されています']];
        }

        $passwordHash = $this->passwordValidator->hash($password);

        $user = User::create([
            'email' => $email,
            'username' => $username,
            'password_hash' => $passwordHash,
            'display_name' => $displayName,
            'email_verified' => 0,
        ]);

        return [
            'success' => true,
            'user' => [
                'id' => $user->id,
                'uuid' => $user->uuid,
                'email' => $user->email,
                'username' => $user->username,
                'display_name' => $user->display_name,
            ],
        ];
    }

    public function login(array $input, string $ip, string $userAgent): array
    {
        $email = $input['email'] ?? '';
        $password = $input['password'] ?? '';

        $identifier = $ip . '|' . strtolower($email);

        if (!$this->rateLimiter->isAllowed($identifier, 'login')) {
            $remaining = $this->rateLimiter->getLockoutRemaining($identifier, 'login');
            return [
                'success' => false,
                'errors' => ["試行回数が多すぎます。{$remaining}秒後に再度お試しください"],
            ];
        }

        $user = User::findByEmail($email);
        if (!$user) {
            $this->rateLimiter->recordAttempt($identifier, 'login', false);
            return ['success' => false, 'errors' => ['メールアドレスまたはパスワードが正しくありません']];
        }

        if ($user->status !== 'active') {
            return ['success' => false, 'errors' => ['このアカウントは利用できません']];
        }

        if (!$this->passwordValidator->verify($password, $user->password_hash)) {
            $user->incrementFailedLoginAttempts();
            $this->rateLimiter->recordAttempt($identifier, 'login', false);
            return ['success' => false, 'errors' => ['メールアドレスまたはパスワードが正しくありません']];
        }

        $user->resetFailedLoginAttempts();
        $user->updateLastLogin($ip);
        $this->rateLimiter->resetAttempts($identifier, 'login');

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

        // リフレッシュトークンをDBに保存
        RefreshToken::create(
            $user->id,
            $refreshToken,
            (int)($_ENV['JWT_REFRESH_EXPIRY'] ?? 2592000),
            $ip,
            $userAgent
        );

        return [
            'success' => true,
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'expires_in' => (int)($_ENV['JWT_EXPIRY'] ?? 3600),
        ];
    }

    public function refresh(string $refreshTokenString): array
    {
        $decoded = $this->jwtService->validateToken($refreshTokenString, 'refresh');
        if (!$decoded) {
            return ['success' => false, 'errors' => ['リフレッシュトークンが無効または期限切れです']];
        }

        // DBでトークンの有効性を確認
        $tokenRecord = RefreshToken::findByToken($refreshTokenString);
        if (!$tokenRecord) {
            return ['success' => false, 'errors' => ['リフレッシュトークンが無効または期限切れです']];
        }

        $user = User::findById($tokenRecord->user_id);
        if (!$user || $user->status !== 'active') {
            return ['success' => false, 'errors' => ['ユーザーが存在しないか利用できません']];
        }

        // 古いトークンを失効
        $tokenRecord->revoke();

        // 新しいトークンを発行
        $newAccessToken = $this->jwtService->createAccessToken([
            'sub' => $user->uuid,
            'user_id' => $user->id,
            'email' => $user->email,
            'username' => $user->username,
        ]);

        $newRefreshToken = $this->jwtService->createRefreshToken([
            'sub' => $user->uuid,
            'user_id' => $user->id,
        ]);

        // 新しいリフレッシュトークンを保存
        RefreshToken::create(
            $user->id,
            $newRefreshToken,
            (int)($_ENV['JWT_REFRESH_EXPIRY'] ?? 2592000),
            $tokenRecord->ip_address ?? '0.0.0.0',
            $tokenRecord->user_agent ?? 'unknown'
        );

        return [
            'success' => true,
            'access_token' => $newAccessToken,
            'refresh_token' => $newRefreshToken,
            'expires_in' => (int)($_ENV['JWT_EXPIRY'] ?? 3600),
        ];
    }

    public function logout(string $authHeader, ?string $refreshTokenString = null): array
    {
        if (str_starts_with($authHeader, 'Bearer ')) {
            $token = substr($authHeader, 7);
            $decoded = $this->jwtService->validateToken($token, 'access');
            
            if ($decoded && isset($decoded->user_id)) {
                // リフレッシュトークンが指定されていればそれを失効
                if ($refreshTokenString) {
                    $tokenRecord = RefreshToken::findByToken($refreshTokenString);
                    if ($tokenRecord && $tokenRecord->user_id === (int)$decoded->user_id) {
                        $tokenRecord->revoke();
                    }
                } else {
                    // すべてのリフレッシュトークンを失効
                    RefreshToken::revokeAllForUser((int)$decoded->user_id);
                }
            }
        }

        return ['success' => true, 'message' => 'ログアウトしました'];
    }

    public function me(string $authHeader): array
    {
        if (!str_starts_with($authHeader, 'Bearer ')) {
            return ['success' => false, 'errors' => ['認証情報が不足しています']];
        }

        $token = substr($authHeader, 7);
        $decoded = $this->jwtService->validateToken($token, 'access');
        if (!$decoded) {
            return ['success' => false, 'errors' => ['トークンが無効または期限切れです']];
        }

        $user = User::findById((int)$decoded->user_id);
        if (!$user) {
            return ['success' => false, 'errors' => ['ユーザーが存在しません']];
        }

        return [
            'success' => true,
            'user' => [
                'id' => $user->id,
                'uuid' => $user->uuid,
                'email' => $user->email,
                'username' => $user->username,
                'display_name' => $user->display_name,
            ],
        ];
    }
}
