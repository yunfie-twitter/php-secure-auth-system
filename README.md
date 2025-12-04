# PHP Secure Auth System

🔐 エンタープライズグレードのPHP認証システム - JWT、OpenID Connect、SSO対応

## 特徴

### セキュリティ機能
- ✅ **JWT トークン認証** - アクセストークン + リフレッシュトークン
- ✅ **強力なパスワードポリシー** - 長さ、複雑性、脆弱パスワードチェック
- ✅ **ソルト付きハッシュ化** - bcryptによるレインボーテーブル攻撃防止
- ✅ **レート制限** - ログイン試行回数制限と自動ロックアウト
- ✅ **CSRF保護** - トークンベースのクロスサイトリクエストフォージェリ対策
- ✅ **XSS対策** - 入出力のサニタイゼーション
- ✅ **OpenID Connect対応** - 標準的なOAuth 2.0 / OIDC統合
- ✅ **SSO（シングルサインオン）** - エンタープライズ認証統合
- ✅ **監査ログ** - 全ての認証イベントを記録

### 技術スタック
- PHP 8.1+
- MySQL 8.0+
- JWT (firebase/php-jwt)
- OpenID Connect
- PSR-4 オートローディング

## インストール

### 必要要件
- PHP 8.1以上
- MySQL 8.0以上
- Composer

### セットアップ手順

1. **リポジトリをクローン**
```bash
git clone https://github.com/yunfie-twitter/php-secure-auth-system.git
cd php-secure-auth-system
```

2. **依存関係をインストール**
```bash
composer install
```

3. **環境設定**
```bash
cp .env.example .env
# .envファイルを編集してデータベース情報などを設定
```

4. **データベースをセットアップ**
```bash
mysql -u root -p < database/schema.sql
```

5. **権限を設定**
```bash
chmod 755 public
chmod 644 .env
```

## 使い方

### ユーザー登録
```php
POST /api/auth/register
{
    "email": "user@example.com",
    "username": "username",
    "password": "SecureP@ssw0rd123!",
    "display_name": "Display Name"
}
```

### ログイン
```php
POST /api/auth/login
{
    "email": "user@example.com",
    "password": "SecureP@ssw0rd123!"
}
```

レスポンス:
```json
{
    "success": true,
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "expires_in": 3600
}
```

### トークンリフレッシュ
```php
POST /api/auth/refresh
{
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

### ログアウト
```php
POST /api/auth/logout
Authorization: Bearer {access_token}
```

## セキュリティ設定

### パスワードポリシー
`.env`ファイルで設定可能:
```env
PASSWORD_MIN_LENGTH=12
PASSWORD_REQUIRE_UPPERCASE=1
PASSWORD_REQUIRE_LOWERCASE=1
PASSWORD_REQUIRE_NUMBERS=1
PASSWORD_REQUIRE_SPECIAL=1
```

### レート制限
```env
RATE_LIMIT_ATTEMPTS=5      # 最大試行回数
RATE_LIMIT_WINDOW=900      # 15分間
LOCKOUT_DURATION=1800      # 30分間ロック
```

### OpenID Connect設定
```env
OIDC_ENABLED=true
OIDC_ISSUER=https://your-oidc-provider.com
OIDC_CLIENT_ID=your_client_id
OIDC_CLIENT_SECRET=your_client_secret
OIDC_REDIRECT_URI=http://localhost/callback
```

## API エンドポイント

| メソッド | エンドポイント | 説明 |
|---------|--------------|------|
| POST | /api/auth/register | ユーザー登録 |
| POST | /api/auth/login | ログイン |
| POST | /api/auth/logout | ログアウト |
| POST | /api/auth/refresh | トークン更新 |
| GET | /api/auth/me | ユーザー情報取得 |
| POST | /api/auth/password/reset | パスワードリセット要求 |
| POST | /api/auth/password/update | パスワード更新 |
| GET | /api/auth/oidc/login | OpenID Connect ログイン |
| GET | /api/auth/oidc/callback | OpenID Connect コールバック |
| GET | /api/auth/sso/login | SSO ログイン |
| GET | /api/auth/sso/callback | SSO コールバック |

## セキュリティ機能詳細

### 1. パスワードハッシュ化
- bcryptアルゴリズム使用（cost=12）
- 自動ソルト生成
- レインボーテーブル攻撃に対する耐性

### 2. JWT トークン
- アクセストークン（短命: 1時間）
- リフレッシュトークン（長命: 30日）
- トークン失効機能
- セキュアなトークンストレージ

### 3. CSRF保護
- トークンベースの検証
- タイミングセーフな比較
- トークンの自動有効期限

### 4. XSS対策
- 入力の自動サニタイゼーション
- 出力のエスケープ処理
- Content Security Policy対応

### 5. レート制限
- IPベースの制限
- アカウントベースの制限
- 段階的なロックアウト
- 自動クリーンアップ

## 開発

### ディレクトリ構造
```
php-secure-auth-system/
├── src/
│   ├── Config/          # 設定クラス
│   ├── Security/        # セキュリティユーティリティ
│   ├── Auth/            # 認証ロジック
│   ├── Models/          # データモデル
│   └── Controllers/     # APIコントローラー
├── public/              # 公開ディレクトリ
├── database/            # データベーススキーマ
├── tests/               # テスト
└── vendor/              # Composer依存関係
```

## ライセンス

MIT License

## 作者

ゆんふぃ ([@yunfie_misskey](https://twitter.com/yunfie_misskey))

## 貢献

プルリクエストを歓迎します！バグ報告や機能提案はIssuesでお願いします。

## セキュリティ

セキュリティ上の問題を発見した場合は、公開せずに yunfie_tw@proton.me まで直接ご連絡ください。