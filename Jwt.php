<?php

namespace App;

/**
 * JWT (JSON Web Token) 工具类
 * 支持 HS256 / HS384 / HS512 签名算法
 * 兼容 PHP 7.3+
 */
class Jwt
{
    /** @var string 密钥 */
    private $secret;

    /** @var string 签名算法 */
    private $algo;

    /** @var array 算法映射 */
    private static $algos = [
        'HS256' => 'sha256',
        'HS384' => 'sha384',
        'HS512' => 'sha512',
    ];

    /**
     * @param string $secret 密钥
     * @param string $algo   签名算法 (HS256|HS384|HS512)
     */
    public function __construct($secret, $algo = 'HS256')
    {
        if (empty($secret)) {
            throw new \InvalidArgumentException('密钥不能为空');
        }

        if (!isset(self::$algos[$algo])) {
            throw new \InvalidArgumentException('不支持的算法: ' . $algo);
        }

        $this->secret = $secret;
        $this->algo = $algo;
    }

    /**
     * 生成 JWT Token
     *
     * @param array $payload 载荷数据
     * @param int   $exp     过期时间（秒），0 表示不设置
     * @return string
     */
    public function encode(array $payload, $exp = 3600)
    {
        $header = [
            'typ' => 'JWT',
            'alg' => $this->algo,
        ];

        // 自动添加签发时间
        if (!isset($payload['iat'])) {
            $payload['iat'] = time();
        }

        // 设置过期时间
        if ($exp > 0 && !isset($payload['exp'])) {
            $payload['exp'] = time() + $exp;
        }

        $segments = [];
        $segments[] = self::base64UrlEncode(json_encode($header, JSON_UNESCAPED_UNICODE));
        $segments[] = self::base64UrlEncode(json_encode($payload, JSON_UNESCAPED_UNICODE));

        $signingInput = implode('.', $segments);
        $signature = $this->sign($signingInput);
        $segments[] = self::base64UrlEncode($signature);

        return implode('.', $segments);
    }

    /**
     * 解析并验证 JWT Token
     *
     * @param string $token
     * @return array 解析后的 payload
     * @throws JwtException
     */
    public function decode($token)
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new JwtException('Token格式无效');
        }

        list($headerB64, $payloadB64, $signatureB64) = $parts;

        // 验证签名
        $signingInput = $headerB64 . '.' . $payloadB64;
        $signature = self::base64UrlDecode($signatureB64);

        if (!$this->verify($signingInput, $signature)) {
            throw new JwtException('签名验证失败');
        }

        // 解析 header
        $header = json_decode(self::base64UrlDecode($headerB64), true);
        if ($header === null) {
            throw new JwtException('Header解析失败');
        }

        // 验证算法
        if (!isset($header['alg']) || $header['alg'] !== $this->algo) {
            throw new JwtException('算法不匹配');
        }

        // 解析 payload
        $payload = json_decode(self::base64UrlDecode($payloadB64), true);
        if ($payload === null) {
            throw new JwtException('Payload解析失败');
        }

        // 验证过期时间
        if (isset($payload['exp']) && $payload['exp'] < time()) {
            throw new JwtException('Token已过期');
        }

        // 验证生效时间
        if (isset($payload['nbf']) && $payload['nbf'] > time()) {
            throw new JwtException('Token尚未生效');
        }

        return $payload;
    }

    /**
     * 仅解析 payload，不验证签名（用于调试）
     *
     * @param string $token
     * @return array|null
     */
    public function parse($token)
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            return null;
        }

        $payload = json_decode(self::base64UrlDecode($parts[1]), true);

        return $payload;
    }

    /**
     * 检查 Token 是否有效（不抛异常）
     *
     * @param string $token
     * @return bool
     */
    public function isValid($token)
    {
        try {
            $this->decode($token);
            return true;
        } catch (JwtException $e) {
            return false;
        }
    }

    /**
     * 刷新 Token（重新签发，保留原 payload）
     *
     * @param string $token 原 Token
     * @param int    $exp   新的过期时间（秒）
     * @return string 新 Token
     * @throws JwtException
     */
    public function refresh($token, $exp = 3600)
    {
        $payload = $this->decode($token);

        // 移除旧的时间字段，重新生成
        unset($payload['iat'], $payload['exp']);

        return $this->encode($payload, $exp);
    }

    /**
     * HMAC 签名
     *
     * @param string $input
     * @return string
     */
    private function sign($input)
    {
        return hash_hmac(self::$algos[$this->algo], $input, $this->secret, true);
    }

    /**
     * 验证签名（使用时间安全比较）
     *
     * @param string $input
     * @param string $signature
     * @return bool
     */
    private function verify($input, $signature)
    {
        $expected = $this->sign($input);
        return hash_equals($expected, $signature);
    }

    /**
     * Base64Url 编码
     *
     * @param string $data
     * @return string
     */
    private static function base64UrlEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Base64Url 解码
     *
     * @param string $data
     * @return string
     */
    private static function base64UrlDecode($data)
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode(strtr($data, '-_', '+/'));
    }
}
