// Package auth 提供认证与授权的纯逻辑实现：密码哈希、令牌签发解析、
// 权限码体系。本包**不依赖数据库、HTTP 与全局状态**，因此可被单测完全覆盖，
// 也可安全地被中间件与业务层复用。
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params argon2id 参数。
//
// 参数强度直接决定离线爆破成本。默认值取 m=64MiB / t=2 / p=2：
// 高于 OWASP 的最低建议（m=19MiB, t=2, p=1），单次校验约 100ms，
// 对登录接口而言性能完全可接受，同时让 GPU 爆破的性价比大幅下降。
type Argon2Params struct {
	Memory      uint32 // 内存用量，单位 KiB
	Iterations  uint32 // 迭代次数
	Parallelism uint8  // 并行度
	SaltLength  uint32 // 盐长度，单位字节
	KeyLength   uint32 // 派生密钥长度，单位字节
}

// DefaultArgon2Params 返回生产使用的默认参数。
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Memory:      64 * 1024,
		Iterations:  2,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// 密码哈希相关错误。
var (
	ErrInvalidHashFormat   = errors.New("auth: 密码哈希格式非法")
	ErrIncompatibleVersion = errors.New("auth: 不兼容的 argon2 版本")
	ErrEmptyPassword       = errors.New("auth: 密码不能为空")
)

// 密码策略约束。
const (
	// MinPasswordLength 与 MaxPasswordLength 双向设限：
	// 下限防弱口令，上限防「超长密码 DoS」（argon2 对长度敏感）。
	MinPasswordLength = 8
	MaxPasswordLength = 128
)

// ValidatePasswordStrength 校验密码强度。返回中文错误信息，可直接回显给用户。
func ValidatePasswordStrength(password string) error {
	if password == "" {
		return ErrEmptyPassword
	}
	// 按 rune 计数，避免中文密码被字节长度误判
	n := len([]rune(password))
	if n < MinPasswordLength {
		return fmt.Errorf("密码长度不得少于 %d 位", MinPasswordLength)
	}
	if n > MaxPasswordLength {
		return fmt.Errorf("密码长度不得超过 %d 位", MaxPasswordLength)
	}
	return nil
}

// HashPassword 生成 argon2id 哈希，输出标准 PHC 字符串：
//
//	$argon2id$v=19$m=65536,t=2,p=2$<base64(salt)>$<base64(hash)>
//
// 采用 PHC 格式而非自定义拼接，好处是参数随哈希一起存储，
// 未来调整强度时旧哈希仍可校验，无需强制全员改密。
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", ErrEmptyPassword
	}
	return HashPasswordWith(password, DefaultArgon2Params())
}

// HashPasswordWith 使用指定参数生成哈希。测试中传弱参数以提速。
func HashPasswordWith(password string, p Argon2Params) (string, error) {
	if password == "" {
		return "", ErrEmptyPassword
	}
	if p.SaltLength == 0 || p.KeyLength == 0 {
		return "", fmt.Errorf("auth: 非法的 argon2 参数（salt=%d key=%d）", p.SaltLength, p.KeyLength)
	}

	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: 生成盐失败: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	// 用 RawStdEncoding（无填充）与主流实现保持一致
	enc := base64.RawStdEncoding
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism,
		enc.EncodeToString(salt), enc.EncodeToString(key),
	), nil
}

// VerifyPassword 校验明文密码与 PHC 哈希是否匹配。
//
// 返回值语义：
//   - (true,  nil) 密码正确
//   - (false, nil) 密码错误
//   - (false, err) 哈希本身损坏或参数不受支持（属于数据异常，应告警而非当作密码错误）
func VerifyPassword(password, encoded string) (bool, error) {
	p, salt, want, err := decodeHash(encoded)
	if err != nil {
		return false, err
	}

	got := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, uint32(len(want)))

	// 必须用常量时间比对，否则可依据响应耗时逐字节推断哈希
	if subtle.ConstantTimeCompare(got, want) == 1 {
		return true, nil
	}
	return false, nil
}

// decodeHash 解析 PHC 字符串，返回参数、盐与派生密钥。
func decodeHash(encoded string) (Argon2Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	// 形如 ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash] 共 6 段
	if len(parts) != 6 || parts[0] != "" {
		return Argon2Params{}, nil, nil, ErrInvalidHashFormat
	}
	if parts[1] != "argon2id" {
		return Argon2Params{}, nil, nil, fmt.Errorf("%w: 算法为 %q", ErrInvalidHashFormat, parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return Argon2Params{}, nil, nil, ErrInvalidHashFormat
	}
	if version != argon2.Version {
		return Argon2Params{}, nil, nil, fmt.Errorf("%w: v=%d (需要 v=%d)",
			ErrIncompatibleVersion, version, argon2.Version)
	}

	var p Argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return Argon2Params{}, nil, nil, ErrInvalidHashFormat
	}
	// 上限护栏：恶意构造的超大 m 会让校验函数直接吃光内存
	if p.Memory == 0 || p.Memory > 1<<20 || p.Iterations == 0 || p.Parallelism == 0 {
		return Argon2Params{}, nil, nil, fmt.Errorf("%w: 参数越界 m=%d t=%d p=%d",
			ErrInvalidHashFormat, p.Memory, p.Iterations, p.Parallelism)
	}

	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[4])
	if err != nil {
		return Argon2Params{}, nil, nil, ErrInvalidHashFormat
	}
	key, err := enc.DecodeString(parts[5])
	if err != nil {
		return Argon2Params{}, nil, nil, ErrInvalidHashFormat
	}
	if len(salt) == 0 || len(key) == 0 {
		return Argon2Params{}, nil, nil, ErrInvalidHashFormat
	}

	p.SaltLength = uint32(len(salt))
	p.KeyLength = uint32(len(key))
	return p, salt, key, nil
}
