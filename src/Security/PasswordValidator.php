<?php

namespace App\Security;

class PasswordValidator
{
    private int $minLength;
    private bool $requireUppercase;
    private bool $requireLowercase;
    private bool $requireNumbers;
    private bool $requireSpecial;

    public function __construct(
        ?int $minLength = null,
        ?bool $requireUppercase = null,
        ?bool $requireLowercase = null,
        ?bool $requireNumbers = null,
        ?bool $requireSpecial = null
    ) {
        $this->minLength = $minLength ?? (int)($_ENV['PASSWORD_MIN_LENGTH'] ?? 12);
        $this->requireUppercase = $requireUppercase ?? (bool)($_ENV['PASSWORD_REQUIRE_UPPERCASE'] ?? true);
        $this->requireLowercase = $requireLowercase ?? (bool)($_ENV['PASSWORD_REQUIRE_LOWERCASE'] ?? true);
        $this->requireNumbers = $requireNumbers ?? (bool)($_ENV['PASSWORD_REQUIRE_NUMBERS'] ?? true);
        $this->requireSpecial = $requireSpecial ?? (bool)($_ENV['PASSWORD_REQUIRE_SPECIAL'] ?? true);
    }

    public function validate(string $password): array
    {
        $errors = [];

        if (strlen($password) < $this->minLength) {
            $errors[] = "パスワードは{$this->minLength}文字以上である必要があります";
        }

        if ($this->requireUppercase && !preg_match('/[A-Z]/', $password)) {
            $errors[] = 'パスワードには大文字を含める必要があります';
        }

        if ($this->requireLowercase && !preg_match('/[a-z]/', $password)) {
            $errors[] = 'パスワードには小文字を含める必要があります';
        }

        if ($this->requireNumbers && !preg_match('/[0-9]/', $password)) {
            $errors[] = 'パスワードには数字を含める必要があります';
        }

        if ($this->requireSpecial && !preg_match('/[^A-Za-z0-9]/', $password)) {
            $errors[] = 'パスワードには特殊文字を含める必要があります';
        }

        // Common weak passwords check
        $weakPasswords = [
            'password123', 'admin123', 'qwerty123', 'welcome123',
            '12345678', 'password', 'admin', 'letmein'
        ];

        if (in_array(strtolower($password), $weakPasswords)) {
            $errors[] = 'このパスワードは脆弱すぎます';
        }

        return [
            'valid' => empty($errors),
            'errors' => $errors
        ];
    }

    public function hash(string $password): string
    {
        // password_hash automatically generates a secure salt
        // and uses bcrypt by default (BCRYPT algorithm)
        return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    }

    public function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }
}