# PHP Secure Auth System

🔐 エンタープライズグレードのPHP認証システム - JWT、OpenID Connect、SSO対応

## 特徴

### セキュリティ機能
- ✅ **JWT トークン認証** - アクセストークン + リフレッシュトークン
- ✅ **リフレッシュトークン永続化** - データベースでトークン管理・失効制御
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
- OpenID Connect (jumbojett/openid-connect-php)
- PSR-4 オートローディング

## インストール

### 必要要件
- PHP 8.1以上
- MySQL 8.0以上
- Composer
- cURL拡張（SSO/OIDC使用時）

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

6. **開発サーバー起動**
```bash
php -S localhost:8000 -t public
```

## 使い方

### 1. CSRFトークン取得
```bash
curl http://localhost:8000/api/auth/csrf-token
```

レスポンス:
```json
{
    "csrf_token": "abc123..."
}
```

### 2. ユーザー登録
```bash
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: abc123..." \
  -d '{
    "email": "user@example.com",
    "username": "username",
    "password": "SecureP@ssw0rd123!",
    "display_name": "Display Name"
  }'
```

レスポンス:
```json
{
    "success": true,
    "user": {
        "id": 1,
        "uuid": "550e8400-e29b-41d4-a716-446655440000",
        "email": "user@example.com",
        "username": "username",
        "display_name": "Display Name"
    }
}
```

### 3. ログイン
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: abc123..." \
  -d '{
    "email": "user@example.com",
    "password": "SecureP@ssw0rd123!"
  }'
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

### 4. トークンリフレッシュ
```bash
curl -X POST http://localhost:8000/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
  }'
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

### 5. ユーザー情報取得
```bash
curl http://localhost:8000/api/auth/me \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc..."
```

レスポンス:
```json
{
    "success": true,
    "user": {
        "id": 1,
        "uuid": "550e8400-e29b-41d4-a716-446655440000",
        "email": "user@example.com",
        "username": "username",
        "display_name": "Display Name"
    }
}
```

### 6. ログアウト
```bash
# 特定のリフレッシュトークンのみ失効
curl -X POST http://localhost:8000/api/auth/logout \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc..." \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
  }'

# 全てのリフレッシュトークンを失効（全デバイスからログアウト）
curl -X POST http://localhost:8000/api/auth/logout \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc..."
```

## OpenID Connect (OIDC) 統合

### 設定

`.env`ファイルでOIDCを有効化:
```env
OIDC_ENABLED=true
OIDC_ISSUER=https://accounts.google.com
OIDC_CLIENT_ID=your_client_id
OIDC_CLIENT_SECRET=your_client_secret
OIDC_REDIRECT_URI=http://localhost:8000/api/auth/oidc/callback
OIDC_SCOPES=openid profile email
```

### 使用方法

1. **OIDCログイン開始**
```bash
# ブラウザで以下にアクセス
http://localhost:8000/api/auth/oidc/login
```

2. **コールバック処理**

OIDCプロバイダーから自動的に `/api/auth/oidc/callback` にリダイレクトされ、
JWTトークンが発行されます。

### 対応プロバイダー例

- Google
- Microsoft Azure AD
- Okta
- Auth0
- Keycloak
- その他OpenID Connect準拠のプロバイダー

## SSO (シングルサインオン) 統合

### 設定

`.env`ファイルでSSOを有効化:
```env
SSO_ENABLED=true
SSO_PROVIDER_NAME=Corporate SSO
SSO_PROVIDER_URL=https://sso.example.com
SSO_CALLBACK_URL=http://localhost:8000/api/auth/sso/callback
```

### 使用方法

1. **SSOログイン開始**
```bash
# ブラウザで以下にアクセス（リターンURL指定可能）
http://localhost:8000/api/auth/sso/login?return_url=/dashboard
```

2. **コールバック処理**

SSOプロバイダーから `/api/auth/sso/callback` にリダイレクトされ、
認証成功後は指定されたリターンURLにトークン付きでリダイレクトされます。

## API エンドポイント

| メソッド | エンドポイント | 説明 | 認証 | CSRF |
|---------|--------------|------|-----|------|
| GET | /api/auth/csrf-token | CSRFトークン取得 | ❌ | ❌ |
| POST | /api/auth/register | ユーザー登録 | ❌ | ✅ |
| POST | /api/auth/login | ログイン | ❌ | ✅ |
| POST | /api/auth/refresh | トークン更新 | ❌ | ❌ |
| POST | /api/auth/logout | ログアウト | ✅ | ❌ |
| GET | /api/auth/me | ユーザー情報取得 | ✅ | ❌ |
| GET | /api/auth/oidc/login | OIDC ログイン開始 | ❌ | ❌ |
| GET | /api/auth/oidc/callback | OIDC コールバック | ❌ | ❌ |
| GET | /api/auth/sso/login | SSO ログイン開始 | ❌ | ❌ |
| GET | /api/auth/sso/callback | SSO コールバック | ❌ | ❌ |

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

### JWT設定

```env
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_ALGORITHM=HS256
JWT_EXPIRY=3600              # アクセストークン有効期限（1時間）
JWT_REFRESH_EXPIRY=2592000   # リフレッシュトークン有効期限（30日）
```

### CORS設定

```env
CORS_ALLOWED_ORIGINS=http://localhost,http://localhost:3000
CORS_ALLOWED_METHODS=GET,POST,PUT,DELETE,OPTIONS
CORS_ALLOWED_HEADERS=Content-Type,Authorization,X-CSRF-Token
```

## セキュリティ機能詳細

### 1. パスワードハッシュ化
- bcryptアルゴリズム使用（cost=12）
- 自動ソルト生成
- レインボーテーブル攻撃に対する耐性

### 2. JWT トークン
- アクセストークン（短命: 1時間）
- リフレッシュトークン（長命: 30日）
- トークン失効機能（個別 or 全デバイス）
- データベースでトークン管理

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

### 6. リフレッシュトークン永続化
- SHA-256ハッシュでDB保存
- トークンローテーション
- IP・User-Agent記録
- 期限切れトークン自動削除

### 7. OpenID Connect
- 標準的なOAuth 2.0フロー
- 複数プロバイダー対応
- 自動ユーザー作成 or リンク
- プロバイダーデータ保存

### 8. SSO統合
- エンタープライズ認証対応
- Authorization Codeフロー
- カスタムリターンURL
- トークン交換・ユーザー情報取得

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

### テーブル構造

- `users` - ユーザー情報
- `refresh_tokens` - リフレッシュトークン管理
- `rate_limits` - レート制限記録
- `password_resets` - パスワードリセット
- `sso_providers` - SSO/OIDCプロバイダー連携
- `audit_logs` - 監査ログ
- `sessions` - セッション管理

## 本番環境への展開

### セキュリティチェックリスト

- [ ] `.env`ファイルでランダムな`JWT_SECRET`を生成
- [ ] `APP_ENV=production`に設定
- [ ] `APP_DEBUG=false`に設定
- [ ] HTTPSを有効化
- [ ] データベース接続を本番用に変更
- [ ] `cookie_secure=true`（HTTPS時のみ）
- [ ] ファイアウォールでデータベースポートを保護
- [ ] 定期的なバックアップを設定
- [ ] 監査ログの監視を設定
- [ ] レート制限値を環境に合わせて調整

### パフォーマンス最適化

- OPcacheを有効化
- データベースインデックスを確認
- 期限切れトークンの定期クリーンアップ設定
- Redis/Memcachedでセッション管理（オプション）

## トラブルシューティング

### よくある問題

**Q: CSRFトークンエラーが出る**

A: セッションが正しく開始されているか確認してください。

**Q: リフレッシュトークンが無効と言われる**

A: トークンは1回のみ使用可能です。使用後は新しいトークンが発行されます。

**Q: OIDCログインが動作しない**

A: cURL拡張が有効になっているか、リダイレクトURIが正しく設定されているか確認してください。

**Q: レート制限に引っかかる**

A: `.env`の`LOCKOUT_DURATION`秒待つか、データベースの`rate_limits`テーブルをクリアしてください。

## ライセンス

MIT License

## 作者

ゆんふぃ ([@yunfie_misskey](https://twitter.com/yunfie_misskey))

## 貢献

プルリクエストを歓迎します！バグ報告や機能提案はIssuesでお願いします。

## セキュリティ

セキュリティ上の問題を発見した場合は、公開せずに yunfie_tw@proton.me まで直接ご連絡ください。

## 参考リンク

- [JWT Best Practices](https://datatracker.ietf.org/doc/html/rfc8725)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OpenID Connect Specification](https://openid.net/connect/)
- [OAuth 2.0 RFC](https://datatracker.ietf.org/doc/html/rfc6749)