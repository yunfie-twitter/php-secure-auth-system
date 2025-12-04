<?php

namespace App\Security;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class JWTService
{
    private string $secret;
    private string $algorithm;
    private int $accessTokenExpiry;
    private int $refreshTokenExpiry;

    public function __construct()
    {
        $this->secret = $_ENV['JWT_SECRET'] ?? 'change-me';
        $this->algorithm = $_ENV['JWT_ALGORITHM'] ?? 'HS256';
        $this->accessTokenExpiry = (int)($_ENV['JWT_EXPIRY'] ?? 3600);
        $this->refreshTokenExpiry = (int)($_ENV['JWT_REFRESH_EXPIRY'] ?? 2592000);
    }

    public function createAccessToken(array $payload): string
    {
        $now = time();
        $basePayload = [
            'iss' => $_ENV['APP_URL'] ?? 'http://localhost',
            'aud' => $_ENV['APP_URL'] ?? 'http://localhost',
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + $this->accessTokenExpiry,
            'type' => 'access'
        ];

        $tokenPayload = array_merge($basePayload, $payload);

        return JWT::encode($tokenPayload, $this->secret, $this->algorithm);
    }

    public function createRefreshToken(array $payload): string
    {
        $now = time();
        $basePayload = [
            'iss' => $_ENV['APP_URL'] ?? 'http://localhost',
            'aud' => $_ENV['APP_URL'] ?? 'http://localhost',
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + $this->refreshTokenExpiry,
            'type' => 'refresh'
        ];

        $tokenPayload = array_merge($basePayload, $payload);

        return JWT::encode($tokenPayload, $this->secret, $this->algorithm);
    }

    public function validateToken(string $token, string $expectedType = 'access'): ?object
    {
        try {
            $decoded = JWT::decode($token, new Key($this->secret, $this->algorithm));

            if (!isset($decoded->type) || $decoded->type !== $expectedType) {
                return null;
            }

            return $decoded;
        } catch (\Throwable $e) {
            return null;
        }
    }
}
