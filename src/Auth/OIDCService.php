<?php

namespace App\Auth;

use Jumbojett\OpenIDConnectClient;
use App\Models\User;
use App\Models\SSOProvider;
use App\Security\JWTService;

class OIDCService
{
    private bool $enabled;
    private ?OpenIDConnectClient $oidc = null;
    private JWTService $jwtService;

    public function __construct()
    {
        $this->enabled = filter_var($_ENV['OIDC_ENABLED'] ?? false, FILTER_VALIDATE_BOOLEAN);
        $this->jwtService = new JWTService();

        if ($this->enabled) {
            $this->oidc = new OpenIDConnectClient(
                $_ENV['OIDC_ISSUER'] ?? '',
                $_ENV['OIDC_CLIENT_ID'] ?? '',
                $_ENV['OIDC_CLIENT_SECRET'] ?? ''
            );

            $this->oidc->setRedirectURL($_ENV['OIDC_REDIRECT_URI'] ?? '');
            
            $scopes = explode(' ', $_ENV['OIDC_SCOPES'] ?? 'openid profile email');
            foreach ($scopes as $scope) {
                $this->oidc->addScope(trim($scope));
            }
        }
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function getAuthorizationUrl(): ?string
    {
        if (!$this->enabled || !$this->oidc) {
            return null;
        }

        try {
            $this->oidc->authenticate();
            return null; // Redirect happens inside authenticate()
        } catch (\Throwable $e) {
            error_log('OIDC Auth URL Error: ' . $e->getMessage());
            return null;
        }
    }

    public function handleCallback(): array
    {
        if (!$this->enabled || !$this->oidc) {
            return ['success' => false, 'errors' => ['OpenID Connect is not enabled']];
        }

        try {
            $this->oidc->authenticate();
            
            $sub = $this->oidc->requestUserInfo('sub');
            $email = $this->oidc->requestUserInfo('email');
            $name = $this->oidc->requestUserInfo('name');
            $preferredUsername = $this->oidc->requestUserInfo('preferred_username');

            if (!$sub) {
                return ['success' => false, 'errors' => ['Invalid OIDC response: missing sub']];
            }

            $ssoProvider = SSOProvider::findByProvider('oidc', $sub);
            
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
                    $username = $preferredUsername ?? explode('@', $email)[0] ?? 'user_' . bin2hex(random_bytes(4));
                    
                    $user = User::create([
                        'email' => $email,
                        'username' => $username,
                        'password_hash' => password_hash(bin2hex(random_bytes(32)), PASSWORD_BCRYPT),
                        'display_name' => $name ?? $username,
                        'email_verified' => 1,
                    ]);
                }

                SSOProvider::create($user->id, 'oidc', $sub, [
                    'email' => $email,
                    'name' => $name,
                    'preferred_username' => $preferredUsername,
                ]);
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
            ];

        } catch (\Throwable $e) {
            error_log('OIDC Callback Error: ' . $e->getMessage());
            return ['success' => false, 'errors' => ['OpenID Connect authentication failed']];
        }
    }
}
