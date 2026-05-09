# PHP JWT

轻量级 PHP JWT (JSON Web Token) 实现，无第三方依赖，兼容 PHP 7.3+。

支持 HS256 / HS384 / HS512 签名算法。

## 安装

```bash
composer require your-vendor/php-jwt
```

或直接引入文件：

```php
require_once 'src/JwtException.php';
require_once 'src/Jwt.php';
```

## 快速开始

```php
<?php

use App\Jwt;
use App\JwtException;

$jwt = new Jwt('your-secret-key');

// 生成 Token（默认1小时过期）
$token = $jwt->encode([
    'uid'  => 1001,
    'name' => '张三',
    'role' => 'admin',
]);

// 验证并解析
try {
    $payload = $jwt->decode($token);
    print_r($payload);
} catch (JwtException $e) {
    echo '验证失败: ' . $e->getMessage();
}
```

## API

### 构造函数

```php
new Jwt(string $secret, string $algo = 'HS256')
```

| 参数 | 类型 | 说明 |
|------|------|------|
| `$secret` | string | 签名密钥 |
| `$algo` | string | 算法：`HS256`、`HS384`、`HS512` |

### 方法

| 方法 | 说明 |
|------|------|
| `encode(array $payload, $exp = 3600)` | 生成 Token，`$exp` 为过期秒数，0 表示不过期 |
| `decode($token)` | 验证签名并解析，失败抛出 `JwtException` |
| `parse($token)` | 仅解析 payload，不验证签名（调试用） |
| `isValid($token)` | 检查 Token 是否有效，返回 `bool` |
| `refresh($token, $exp = 3600)` | 刷新 Token（验证旧 Token 后重新签发） |

## 使用示例

### 生成 Token

```php
$jwt = new Jwt('my-secret');

// 默认1小时过期
$token = $jwt->encode(['uid' => 123]);

// 自定义过期时间（7天）
$token = $jwt->encode(['uid' => 123], 86400 * 7);

// 不设置过期时间
$token = $jwt->encode(['uid' => 123], 0);

// 自定义 claims
$token = $jwt->encode([
    'uid'  => 123,
    'iss'  => 'my-app',
    'sub'  => 'auth',
    'nbf'  => time(),       // 生效时间
    'data' => ['foo' => 'bar'],
]);
```

### 验证 Token

```php
try {
    $payload = $jwt->decode($token);
    echo '用户ID: ' . $payload['uid'];
} catch (JwtException $e) {
    // 可能的错误：
    // - Token格式无效
    // - 签名验证失败
    // - Token已过期
    // - Token尚未生效
    // - 算法不匹配
    echo $e->getMessage();
}
```

### 检查有效性

```php
if ($jwt->isValid($token)) {
    // Token 有效
}
```

### 刷新 Token

```php
// 验证旧 Token 并签发新 Token（2小时过期）
$newToken = $jwt->refresh($oldToken, 7200);
```

### 使用不同算法

```php
$jwt256 = new Jwt('secret', 'HS256');
$jwt384 = new Jwt('secret', 'HS384');
$jwt512 = new Jwt('secret', 'HS512');
```

## Payload 标准字段

| 字段 | 说明 | 自动设置 |
|------|------|----------|
| `iat` | 签发时间 | 是 |
| `exp` | 过期时间 | 是（通过 `$exp` 参数） |
| `nbf` | 生效时间 | 否 |
| `iss` | 签发者 | 否 |
| `sub` | 主题 | 否 |
| `aud` | 接收方 | 否 |

## 安全说明

- 使用 `hash_equals` 进行时间安全的签名比较，防止时序攻击
- 使用 `hash_hmac` 进行 HMAC 签名
- Base64Url 编码符合 RFC 7515 规范
- 请使用足够长度和复杂度的密钥

## 环境要求

- PHP >= 7.3
- 无需额外扩展

## License

MIT
