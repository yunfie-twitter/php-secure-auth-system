<?php

namespace App\Services;

class EmailService
{
    private string $from;
    private string $fromName;

    public function __construct()
    {
        $this->from = $_ENV['MAIL_FROM'] ?? 'noreply@example.com';
        $this->fromName = $_ENV['MAIL_FROM_NAME'] ?? 'Secure Auth System';
    }

    public function sendVerificationEmail(string $to, string $username, string $token): bool
    {
        $appUrl = $_ENV['APP_URL'] ?? 'http://localhost:8000';
        $verificationUrl = $appUrl . '/verify-email.html?token=' . urlencode($token);

        $subject = 'メールアドレスの確認';
        $message = $this->getVerificationEmailTemplate($username, $verificationUrl);

        return $this->send($to, $subject, $message);
    }

    public function sendPasswordResetEmail(string $to, string $username, string $token): bool
    {
        $appUrl = $_ENV['APP_URL'] ?? 'http://localhost:8000';
        $resetUrl = $appUrl . '/reset-password.html?token=' . urlencode($token);

        $subject = 'パスワードリセットのご案内';
        $message = $this->getPasswordResetEmailTemplate($username, $resetUrl);

        return $this->send($to, $subject, $message);
    }

    private function send(string $to, string $subject, string $message): bool
    {
        $headers = [
            'MIME-Version: 1.0',
            'Content-Type: text/html; charset=UTF-8',
            'From: ' . $this->fromName . ' <' . $this->from . '>',
        ];

        // 本番環境ではSMTPライブラリ（PHPMailer等）を使用することを推奨
        return mail($to, $subject, $message, implode("\r\n", $headers));
    }

    private function getVerificationEmailTemplate(string $username, string $verificationUrl): string
    {
        return '
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
                .container { max-width: 600px; margin: 0 auto; padding: 40px 20px; }
                .header { text-align: center; margin-bottom: 40px; }
                .header h1 { color: #667eea; margin: 0; }
                .content { background: #f9fafb; padding: 30px; border-radius: 8px; }
                .button { display: inline-block; padding: 14px 28px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; border-radius: 6px; font-weight: 600; }
                .footer { margin-top: 30px; text-align: center; color: #6b7280; font-size: 14px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 Secure Auth System</h1>
                </div>
                <div class="content">
                    <h2>メールアドレスの確認</h2>
                    <p>こんにちは、' . htmlspecialchars($username) . ' さん</p>
                    <p>アカウント登録ありがとうございます。以下のボタンをクリックしてメールアドレスを確認してください。</p>
                    <p style="text-align: center; margin: 30px 0;">
                        <a href="' . htmlspecialchars($verificationUrl) . '" class="button">メールアドレスを確認する</a>
                    </p>
                    <p style="font-size: 14px; color: #6b7280;">
                        ボタンが機能しない場合は、以下のリンクをブラウザにコピーしてください：<br>
                        <a href="' . htmlspecialchars($verificationUrl) . '">' . htmlspecialchars($verificationUrl) . '</a>
                    </p>
                    <p style="font-size: 14px; color: #6b7280; margin-top: 20px;">
                        このメールに心当たりがない場合は、無視してください。
                    </p>
                </div>
                <div class="footer">
                    <p>&copy; 2025 Secure Auth System. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        ';
    }

    private function getPasswordResetEmailTemplate(string $username, string $resetUrl): string
    {
        return '
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
                .container { max-width: 600px; margin: 0 auto; padding: 40px 20px; }
                .header { text-align: center; margin-bottom: 40px; }
                .header h1 { color: #667eea; margin: 0; }
                .content { background: #f9fafb; padding: 30px; border-radius: 8px; }
                .button { display: inline-block; padding: 14px 28px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; border-radius: 6px; font-weight: 600; }
                .footer { margin-top: 30px; text-align: center; color: #6b7280; font-size: 14px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 Secure Auth System</h1>
                </div>
                <div class="content">
                    <h2>パスワードリセット</h2>
                    <p>こんにちは、' . htmlspecialchars($username) . ' さん</p>
                    <p>パスワードリセットのリクエストを受け付けました。以下のボタンをクリックして新しいパスワードを設定してください。</p>
                    <p style="text-align: center; margin: 30px 0;">
                        <a href="' . htmlspecialchars($resetUrl) . '" class="button">パスワードをリセットする</a>
                    </p>
                    <p style="font-size: 14px; color: #6b7280;">
                        このリンクは24時間有効です。<br>
                        ボタンが機能しない場合は、以下のリンクをブラウザにコピーしてください：<br>
                        <a href="' . htmlspecialchars($resetUrl) . '">' . htmlspecialchars($resetUrl) . '</a>
                    </p>
                    <p style="font-size: 14px; color: #6b7280; margin-top: 20px;">
                        パスワードリセットをリクエストしていない場合は、このメールを無視してください。
                    </p>
                </div>
                <div class="footer">
                    <p>&copy; 2025 Secure Auth System. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        ';
    }
}
