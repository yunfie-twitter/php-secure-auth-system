<?php

namespace App\Models;

use App\Config\Database;
use PDO;

class RefreshToken
{
    public int $id;
    public int $user_id;
    public string $token_hash;
    public string $expires_at;
    public bool $revoked = false;
    public ?string $revoked_at = null;
    public ?string $user_agent = null;
    public ?string $ip_address = null;

    public static function create(int $userId, string $token, int $expiresIn, string $ip, string $userAgent): self
    {
        $db = Database::getConnection();
        
        $tokenHash = hash('sha256', $token);
        $expiresAt = date('Y-m-d H:i:s', time() + $expiresIn);

        $stmt = $db->prepare('
            INSERT INTO refresh_tokens (user_id, token_hash, expires_at, user_agent, ip_address)
            VALUES (:user_id, :token_hash, :expires_at, :user_agent, :ip_address)
        ');

        $stmt->execute([
            'user_id' => $userId,
            'token_hash' => $tokenHash,
            'expires_at' => $expiresAt,
            'user_agent' => $userAgent,
            'ip_address' => $ip,
        ]);

        $id = (int)$db->lastInsertId();
        return self::findById($id);
    }

    public static function findByToken(string $token): ?self
    {
        $db = Database::getConnection();
        $tokenHash = hash('sha256', $token);
        
        $stmt = $db->prepare('
            SELECT * FROM refresh_tokens 
            WHERE token_hash = :token_hash 
            AND revoked = 0 
            AND expires_at > NOW()
            LIMIT 1
        ');
        
        $stmt->execute(['token_hash' => $tokenHash]);
        $data = $stmt->fetch();
        
        return $data ? self::fromArray($data) : null;
    }

    public static function findById(int $id): ?self
    {
        $db = Database::getConnection();
        $stmt = $db->prepare('SELECT * FROM refresh_tokens WHERE id = :id LIMIT 1');
        $stmt->execute(['id' => $id]);
        $data = $stmt->fetch();
        
        return $data ? self::fromArray($data) : null;
    }

    public function revoke(): void
    {
        $db = Database::getConnection();
        $stmt = $db->prepare('
            UPDATE refresh_tokens 
            SET revoked = 1, revoked_at = NOW() 
            WHERE id = :id
        ');
        $stmt->execute(['id' => $this->id]);
        $this->revoked = true;
        $this->revoked_at = date('Y-m-d H:i:s');
    }

    public static function revokeAllForUser(int $userId): void
    {
        $db = Database::getConnection();
        $stmt = $db->prepare('
            UPDATE refresh_tokens 
            SET revoked = 1, revoked_at = NOW() 
            WHERE user_id = :user_id AND revoked = 0
        ');
        $stmt->execute(['user_id' => $userId]);
    }

    public static function cleanupExpired(): void
    {
        $db = Database::getConnection();
        $stmt = $db->prepare('DELETE FROM refresh_tokens WHERE expires_at < NOW()');
        $stmt->execute();
    }

    private static function fromArray(array $data): self
    {
        $token = new self();
        $token->id = (int)$data['id'];
        $token->user_id = (int)$data['user_id'];
        $token->token_hash = $data['token_hash'];
        $token->expires_at = $data['expires_at'];
        $token->revoked = (bool)$data['revoked'];
        $token->revoked_at = $data['revoked_at'] ?? null;
        $token->user_agent = $data['user_agent'] ?? null;
        $token->ip_address = $data['ip_address'] ?? null;
        return $token;
    }
}
