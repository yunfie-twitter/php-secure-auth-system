<?php

namespace App\Security;

use App\Config\Database;
use PDO;

class RateLimiter
{
    private int $maxAttempts;
    private int $timeWindow;
    private int $lockoutDuration;

    public function __construct(
        ?int $maxAttempts = null,
        ?int $timeWindow = null,
        ?int $lockoutDuration = null
    ) {
        $this->maxAttempts = $maxAttempts ?? (int)($_ENV['RATE_LIMIT_ATTEMPTS'] ?? 5);
        $this->timeWindow = $timeWindow ?? (int)($_ENV['RATE_LIMIT_WINDOW'] ?? 900); // 15 minutes
        $this->lockoutDuration = $lockoutDuration ?? (int)($_ENV['LOCKOUT_DURATION'] ?? 1800); // 30 minutes
    }

    public function isAllowed(string $identifier, string $action = 'login'): bool
    {
        $this->cleanupOldAttempts();
        
        $attempts = $this->getAttempts($identifier, $action);
        
        if ($attempts >= $this->maxAttempts) {
            $lockoutRemaining = $this->getLockoutRemaining($identifier, $action);
            return $lockoutRemaining <= 0;
        }

        return true;
    }

    public function recordAttempt(string $identifier, string $action = 'login', bool $success = false): void
    {
        $db = Database::getConnection();
        
        $stmt = $db->prepare("
            INSERT INTO rate_limits (identifier, action, success, created_at)
            VALUES (:identifier, :action, :success, NOW())
        ");
        
        $stmt->execute([
            'identifier' => $identifier,
            'action' => $action,
            'success' => $success ? 1 : 0
        ]);
    }

    public function resetAttempts(string $identifier, string $action = 'login'): void
    {
        $db = Database::getConnection();
        
        $stmt = $db->prepare("
            DELETE FROM rate_limits
            WHERE identifier = :identifier AND action = :action
        ");
        
        $stmt->execute([
            'identifier' => $identifier,
            'action' => $action
        ]);
    }

    public function getAttempts(string $identifier, string $action = 'login'): int
    {
        $db = Database::getConnection();
        
        $stmt = $db->prepare("
            SELECT COUNT(*) as count
            FROM rate_limits
            WHERE identifier = :identifier
            AND action = :action
            AND success = 0
            AND created_at > DATE_SUB(NOW(), INTERVAL :window SECOND)
        ");
        
        $stmt->execute([
            'identifier' => $identifier,
            'action' => $action,
            'window' => $this->timeWindow
        ]);
        
        $result = $stmt->fetch();
        return (int)($result['count'] ?? 0);
    }

    public function getLockoutRemaining(string $identifier, string $action = 'login'): int
    {
        $db = Database::getConnection();
        
        $stmt = $db->prepare("
            SELECT TIMESTAMPDIFF(SECOND, MAX(created_at), NOW()) as elapsed
            FROM rate_limits
            WHERE identifier = :identifier
            AND action = :action
            AND success = 0
            ORDER BY created_at DESC
            LIMIT 1
        ");
        
        $stmt->execute([
            'identifier' => $identifier,
            'action' => $action
        ]);
        
        $result = $stmt->fetch();
        $elapsed = (int)($result['elapsed'] ?? PHP_INT_MAX);
        
        return max(0, $this->lockoutDuration - $elapsed);
    }

    private function cleanupOldAttempts(): void
    {
        $db = Database::getConnection();
        
        $stmt = $db->prepare("
            DELETE FROM rate_limits
            WHERE created_at < DATE_SUB(NOW(), INTERVAL :duration SECOND)
        ");
        
        $stmt->execute(['duration' => max($this->timeWindow, $this->lockoutDuration)]);
    }
}