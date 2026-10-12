package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// 令牌体系常量。
const (
	// MinJWTSecretLength HS256 密钥最小长度。HS256 的安全性完全依赖密钥熵，
	// 短密钥可被离线暴力破解，故启动时硬性拦截。
	MinJWTSecretLength = 32

	// TokenIssuer 签发者标识，写入 iss 声明。
	TokenIssuer = "sec-risk-assistant"

	// TokenUseAccess 令牌用途标记，写入自定义声明 use。
	// 作用是防止未来引入其他类型令牌时发生「令牌混用」。
	TokenUseAccess = "access"
)

// 令牌相关错误。调用方据此区分「需要刷新」与「彻底无效」。
var (
	ErrInvalidToken = errors.New("auth: 令牌无效")
	ErrTokenExpired = errors.New("auth: 令牌已过期")
)

// AccessClaims Access Token 的声明集合。
//
// ⚠️ 刻意**不把权限码写进令牌**。权限码一旦签进 JWT，在令牌有效期内
// 就无法收回——管理员撤销某人角色后，对方还能继续用旧令牌操作 15 分钟。
// 这里的做法是：令牌只承载身份（谁），权限每次请求现查（能做什么）。
// 用户量级（政企内部几十到几百人）+ 主键索引查询，这个代价完全付得起。
type AccessClaims struct {
	jwt.RegisteredClaims
	Username string `json:"name,omitempty"`
	Use      string `json:"use"`

	// IssuedAtMs 签发时刻的毫秒时间戳。
	//
	// JWT 标准的 iat 只精确到秒，无法区分「同一秒内先登出、后重新登录」——
	// 两者会得到相同的 iat，导致刚签发的新令牌被误判为登出前的旧令牌而拒绝。
	// 这里补一个毫秒精度声明专供「令牌生效下界」比较使用。
	IssuedAtMs int64 `json:"iat_ms"`
}

// TokenManager 负责 Access Token 的签发与校验。并发安全（无内部可变状态）。
type TokenManager struct {
	secret []byte
	issuer string
	ttl    time.Duration
}

// NewTokenManager 构建令牌管理器，并校验密钥强度。
func NewTokenManager(secret, issuer string, accessTTL time.Duration) (*TokenManager, error) {
	if len(secret) < MinJWTSecretLength {
		return nil, fmt.Errorf("auth: JWT 密钥长度 %d 不足 %d，请用 openssl rand -hex 32 生成",
			len(secret), MinJWTSecretLength)
	}
	if accessTTL <= 0 {
		return nil, fmt.Errorf("auth: access token TTL 必须为正数，当前 %s", accessTTL)
	}
	if issuer == "" {
		issuer = TokenIssuer
	}
	return &TokenManager{secret: []byte(secret), issuer: issuer, ttl: accessTTL}, nil
}

// TTL 返回 Access Token 有效期，供接口层设置 Cookie MaxAge 使用。
func (m *TokenManager) TTL() time.Duration { return m.ttl }

// IssueAccess 签发 Access Token。
func (m *TokenManager) IssueAccess(userID uint64, username string) (string, error) {
	jti, err := randomHex(16)
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   strconv.FormatUint(userID, 10),
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-30 * time.Second)), // 容忍轻微时钟漂移
			ExpiresAt: jwt.NewNumericDate(now.Add(m.ttl)),
		},
		Username:   username,
		Use:        TokenUseAccess,
		IssuedAtMs: now.UnixMilli(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(m.secret)
	if err != nil {
		return "", fmt.Errorf("auth: 签发访问令牌失败: %w", err)
	}
	return signed, nil
}

// ParseAccess 校验并解析 Access Token。
//
// ⚠️ 必须显式限定签名算法为 HS256。不限定的话，攻击者可把 header 的 alg
// 改成 "none" 或改用非对称算法来绕过签名校验（alg confusion 攻击）。
func (m *TokenManager) ParseAccess(tokenString string) (*AccessClaims, error) {
	claims := &AccessClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		return m.secret, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(m.issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if claims.Use != TokenUseAccess {
		return nil, fmt.Errorf("%w: 令牌用途不匹配", ErrInvalidToken)
	}

	userID, err := claims.UserID()
	if err != nil {
		return nil, err
	}
	_ = userID
	return claims, nil
}

// UserID 从 Subject 声明解析用户 ID。
func (c *AccessClaims) UserID() (uint64, error) {
	id, err := strconv.ParseUint(c.Subject, 10, 64)
	if err != nil || id == 0 {
		return 0, fmt.Errorf("%w: sub 不是合法用户 ID", ErrInvalidToken)
	}
	return id, nil
}

// ---------------------------------------------------------------- 不透明令牌

// NewRefreshToken 生成刷新令牌。
//
// 返回 (明文字符串, 落库哈希)。明文只在响应中交给客户端一次，
// 数据库只保存 SHA-256 摘要——拖库者拿到的摘要无法反推出令牌。
//
// 这里用 SHA-256 而非 argon2：刷新令牌本身是 256 位高熵随机值，
// 不存在「弱口令可被字典爆破」的问题，无需慢哈希，普通摘要即可。
func NewRefreshToken() (plain, hash string, err error) {
	plain, err = randomBase64(32)
	if err != nil {
		return "", "", err
	}
	return plain, HashToken(plain), nil
}

// HashToken 计算令牌的 SHA-256 十六进制摘要。用于落库与比对。
func HashToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// NewCSRFToken 生成 CSRF 双提交令牌。
func NewCSRFToken() (string, error) {
	return randomBase64(32)
}

// NewUUID 生成 RFC 4122 v4 UUID，用于刷新令牌的轮换链标识。
// 自行实现以免为一个函数引入第三方依赖。
func NewUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("auth: 生成 UUID 失败: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC4122
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// SecureCompare 常量时间字符串比对。
//
// 直接写 a == b 会因为「首个不同字节即返回」而泄漏信息：
// 攻击者可通过计时逐字节猜出正确的 CSRF 令牌。
func SecureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// ---------------------------------------------------------------- 内部工具

func randomBase64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: 生成随机数失败: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: 生成随机数失败: %w", err)
	}
	return hex.EncodeToString(b), nil
}
