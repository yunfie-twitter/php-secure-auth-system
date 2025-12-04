<?php

namespace App\Models;

use App\Config\Database;
use PDO;

class SSOProvider
{
    public int $id;
    public int $user_id;
    public string $provider_name;
    public string $provider_user_id;
    public ?array $provider_data = null;

    public static function findByProvider(string $providerName, string $providerUserId): ?self
    {
        $db = Database::getConnection();
        $stmt = $db->prepare('
            SELECT * FROM sso_providers 
            WHERE provider_name = :provider_name 
            AND provider_user_id = :provider_user_id 
            LIMIT 1
        ');
        
        $stmt->execute([
            'provider_name' => $providerName,
            'provider_user_id' => $providerUserId,
        ]);
        
        $data = $stmt->fetch();
        return $data ? self::fromArray($data) : null;
    }

    public static function create(int $userId, string $providerName, string $providerUserId, ?array $providerData = null): self
    {
        $db = Database::getConnection();
        
        $stmt = $db->prepare('
            INSERT INTO sso_providers (user_id, provider_name, provider_user_id, provider_data)
            VALUES (:user_id, :provider_name, :provider_user_id, :provider_data)
        ');

        $stmt->execute([
            'user_id' => $userId,
            'provider_name' => $providerName,
            'provider_user_id' => $providerUserId,
            'provider_data' => $providerData ? json_encode($providerData) : null,
        ]);

        $id = (int)$db->lastInsertId();
        return self::findById($id);
    }

    public static function findById(int $id): ?self
    {
        $db = Database::getConnection();
        $stmt = $db->prepare('SELECT * FROM sso_providers WHERE id = :id LIMIT 1');
        $stmt->execute(['id' => $id]);
        $data = $stmt->fetch();
        
        return $data ? self::fromArray($data) : null;
    }

    private static function fromArray(array $data): self
    {
        $sso = new self();
        $sso->id = (int)$data['id'];
        $sso->user_id = (int)$data['user_id'];
        $sso->provider_name = $data['provider_name'];
        $sso->provider_user_id = $data['provider_user_id'];
        $sso->provider_data = $data['provider_data'] ? json_decode($data['provider_data'], true) : null;
        return $sso;
    }
}
