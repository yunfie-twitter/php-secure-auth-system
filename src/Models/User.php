<?php

namespace App\Models;

use App\Config\Database;
use PDO;

class User
{
    public int $id;
    public string $uuid;
    public string $email;
    public string $password_hash;
    public string $username;
    public ?string $display_name = null;
    public bool $email_verified = false;
    public string $status = 'active';
    public int $failed_login_attempts = 0;
    public ?string $last_login_at = null;
    public ?string $last_login_ip = null;

    public static function findByEmail(string $email): ?self
    {
        $db = Database::getConnection();
        $stmt = $db->prepare('SELECT * FROM users WHERE email = :email AND status != "deleted" LIMIT 1');
        $stmt->execute(['email' => $email]);
        $data = $stmt->fetch();
        return $data ? self::fromArray($data) : null;
    }

    public static function findById(int $id): ?self
    {
        $db = Database::getConnection();
        $stmt = $db->prepare('SELECT * FROM users WHERE id = :id AND status != "deleted" LIMIT 1');
        $stmt->execute(['id' => $id]);
        $data = $stmt->fetch();
        return $data ? self::fromArray($data) : null;
    }

    public static function create(array $data): self
    {
        $db = Database::getConnection();

        $stmt = $db->prepare('
            INSERT INTO users (uuid, email, password_hash, username, display_name, email_verified)
            VALUES (:uuid, :email, :password_hash, :username, :display_name, :email_verified)
        ');

        $uuid = self::generateUuidV4();

        $stmt->execute([
            'uuid' => $uuid,
            'email' => $data['email'],
            'password_hash' => $data['password_hash'],
            'username' => $data['username'],
            'display_name' => $data['display_name'] ?? null,
            'email_verified' => $data['email_verified'] ?? 0,
        ]);

        $id = (int)$db->lastInsertId();
        return self::findById($id);
    }

    public function incrementFailedLoginAttempts(): void
    {
        $db = Database::getConnection();
        $stmt = $db->prepare('UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = :id');
        $stmt->execute(['id' => $this->id]);
    }

    public function resetFailedLoginAttempts(): void
    {
        $db = Database::getConnection();
        $stmt = $db->prepare('UPDATE users SET failed_login_attempts = 0 WHERE id = :id');
        $stmt->execute(['id' => $this->id]);
    }

    public function updateLastLogin(string $ip): void
    {
        $db = Database::getConnection();
        $stmt = $db->prepare('UPDATE users SET last_login_at = NOW(), last_login_ip = :ip WHERE id = :id');
        $stmt->execute([
            'ip' => $ip,
            'id' => $this->id,
        ]);
    }

    private static function fromArray(array $data): self
    {
        $user = new self();
        $user->id = (int)$data['id'];
        $user->uuid = $data['uuid'];
        $user->email = $data['email'];
        $user->password_hash = $data['password_hash'];
        $user->username = $data['username'];
        $user->display_name = $data['display_name'] ?? null;
        $user->email_verified = (bool)$data['email_verified'];
        $user->status = $data['status'];
        $user->failed_login_attempts = (int)$data['failed_login_attempts'];
        $user->last_login_at = $data['last_login_at'] ?? null;
        $user->last_login_ip = $data['last_login_ip'] ?? null;
        return $user;
    }

    private static function generateUuidV4(): string
    {
        $data = random_bytes(16);
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }
}
