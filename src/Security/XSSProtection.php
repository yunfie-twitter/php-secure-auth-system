<?php

namespace App\Security;

class XSSProtection
{
    public static function sanitizeInput(mixed $data): mixed
    {
        if (is_array($data)) {
            return array_map([self::class, 'sanitizeInput'], $data);
        }

        if (is_string($data)) {
            // Remove null bytes
            $data = str_replace(chr(0), '', $data);
            
            // Trim whitespace
            $data = trim($data);
            
            // Convert special characters to HTML entities
            $data = htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }

        return $data;
    }

    public static function sanitizeOutput(mixed $data): mixed
    {
        if (is_array($data)) {
            return array_map([self::class, 'sanitizeOutput'], $data);
        }

        if (is_string($data)) {
            return htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }

        return $data;
    }

    public static function sanitizeForJSON(mixed $data): mixed
    {
        if (is_array($data)) {
            return array_map([self::class, 'sanitizeForJSON'], $data);
        }

        if (is_string($data)) {
            // For JSON output, we need to be careful with special characters
            return htmlspecialchars($data, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        }

        return $data;
    }

    public static function validateEmail(string $email): bool
    {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    public static function sanitizeURL(string $url): string
    {
        return filter_var($url, FILTER_SANITIZE_URL);
    }
}