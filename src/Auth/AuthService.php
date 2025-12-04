<?php

namespace App\Auth;

use App\Models\User;
use App\Models\RefreshToken;
use App\Security\PasswordValidator;
use App\Security\RateLimiter;
use App\Security\JWTService;
use App\Security\XSSProtection;
use App\Security\CSRFProtection;
use App\Services\EmailService;
use App\Config\Database;

class AuthService
{
    public function __construct(
        private PasswordValidator $passwordValidator = new PasswordValidator(),
        private RateLimiter $rateLimiter = new RateLimiter(),
        private JWTService $jwtService = new JWTService(),
        private EmailService $emailService = new EmailService()
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
        
        // メール確認トークン生成
        $verificationToken = bin2hex(random_bytes(32));

        $user = User::create([
            'email' => $email,
            'username' => $username,
            'password_hash' => $passwordHash,
            'display_name' => $displayName,
            'email_verified' => 0,
            'email_verification_token' => $verificationToken,
        ]);

        // 確認メール送信
        $this->emailService->sendVerificationEmail($email, $username, $verificationToken);

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

    public function verifyEmail(string $token): array
    {
        $db = Database::getConnection();
        
        $stmt = $db->prepare('
            SELECT * FROM users 
            WHERE email_verification_token = :token 
            AND email_verified = 0
            LIMIT 1
        ');
        
        $stmt->execute(['token' => $token]);
        $userData = $stmt->fetch();
        
        if (!$userData) {
            return ['success' => false, 'errors' => ['無効な確認トークンです']];
        }
        
        // メール確認フラグを更新
        $stmt = $db->prepare('
            UPDATE users 
            SET email_verified = 1, email_verification_token = NULL 
            WHERE id = :id
        ');
        
        $stmt->execute(['id' => $userData['id']]);
        
        return [
            'success' => true,
            'message' => 'メールアドレスが確認されました',
        ];
    }

    public function resendVerificationEmail(string $email): array
    {
        $user = User::findByEmail($email);
        
        if (!$user) {
            return ['success' => false, 'errors' => ['ユーザーが見つかりません']];
        }
        
        if ($user->email_verified) {
            return ['success' => false, 'errors' => ['このメールアドレスは既に確認済みです']];
        }
        
        // 新しい確認トークン生成
        $verificationToken = bin2hex(random_bytes(32));
        
        $db = Database::getConnection();
        $stmt = $db->prepare('
            UPDATE users 
            SET email_verification_token = :token 
            WHERE id = :id
        ');
        $stmt->execute([
            'token' => $verificationToken,
            'id' => $user->id,
        ]);
        
        // 確認メール再送信
        $this->emailService->sendVerificationEmail($email, $user->username, $verificationToken);
        
        return [
            'success' => true,
            'message' => '確認メールを再送信しました',
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
            'email_verified' => $user->email_verified,
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

        $tokenRecord = RefreshToken::findByToken($refreshTokenString);
        if (!$tokenRecord) {
            return ['success' => false, 'errors' => ['リフレッシュトークンが無効または期限切れです']];
        }

        $user = User::findById($tokenRecord->user_id);
        if (!$user || $user->status !== 'active') {
            return ['success' => false, 'errors' => ['ユーザーが存在しないか利用できません']];
        }

        $tokenRecord->revoke();

        $newAccessToken = $this->jwtService->createAccessToken([
            'sub' => $user->uuid,
            'user_id' => $user->id,
            'email' => $user->email,
            'username' => $user->username,
            'email_verified' => $user->email_verified,
        ]);

        $newRefreshToken = $this->jwtService->createRefreshToken([
            'sub' => $user->uuid,
            'user_id' => $user->id,
        ]);

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
                if ($refreshTokenString) {
                    $tokenRecord = RefreshToken::findByToken($refreshTokenString);
                    if ($tokenRecord && $tokenRecord->user_id === (int)$decoded->user_id) {
                        $tokenRecord->revoke();
                    }
                } else {
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
                'email_verified' => $user->email_verified,
            ],
        ];
    }
}
