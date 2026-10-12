package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// weakParams 单测专用弱参数：只为验证逻辑正确性，不关心抗爆破强度。
// 用默认参数会让整个包的测试跑上十几秒，得不偿失。
var weakParams = Argon2Params{
	Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 8, KeyLength: 16,
}

// ---------------------------------------------------------------- 密码

func TestHashPassword_RoundTrip(t *testing.T) {
	const pwd = "Passw0rd!测试"

	hash, err := HashPasswordWith(pwd, weakParams)
	if err != nil {
		t.Fatalf("生成哈希失败: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Fatalf("哈希前缀不符合 PHC 格式: %s", hash)
	}

	ok, err := VerifyPassword(pwd, hash)
	if err != nil {
		t.Fatalf("校验出错: %v", err)
	}
	if !ok {
		t.Fatal("正确密码被判定为错误")
	}

	ok, err = VerifyPassword(pwd+"x", hash)
	if err != nil {
		t.Fatalf("校验出错: %v", err)
	}
	if ok {
		t.Fatal("错误密码被判定为正确")
	}
}

func TestHashPassword_SaltIsRandom(t *testing.T) {
	h1, _ := HashPasswordWith("same-password", weakParams)
	h2, _ := HashPasswordWith("same-password", weakParams)
	if h1 == h2 {
		t.Fatal("同一密码两次哈希结果相同，说明盐未随机化")
	}
}

func TestHashPasswordWithDefaultParams(t *testing.T) {
	hash, err := HashPassword("DefaultParams@2026")
	if err != nil {
		t.Fatalf("默认参数生成哈希失败: %v", err)
	}
	ok, err := VerifyPassword("DefaultParams@2026", hash)
	if err != nil || !ok {
		t.Fatalf("默认参数校验失败: ok=%v err=%v", ok, err)
	}
	// 默认参数必须落在 PHC 串里，否则未来调参时旧哈希无法校验
	if !strings.Contains(hash, "m=65536,t=2,p=2") {
		t.Fatalf("默认参数未写入 PHC 串: %s", hash)
	}
}

func TestVerifyPassword_BadHash(t *testing.T) {
	cases := map[string]string{
		"段数不足":      "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA",
		"算法不符":      "$argon2i$v=19$m=8192,t=1,p=1$c2FsdA$aGFzaA",
		"版本不符":      "$argon2id$v=13$m=8192,t=1,p=1$c2FsdA$aGFzaA",
		"盐非 base64": "$argon2id$v=19$m=8192,t=1,p=1$!!!!$aGFzaA",
		"参数越界":      "$argon2id$v=19$m=99999999,t=1,p=1$c2FsdA$aGFzaA",
		"空串":        "",
	}
	for name, hash := range cases {
		if _, err := VerifyPassword("whatever", hash); err == nil {
			t.Errorf("%s：期望返回错误，实际 nil", name)
		}
	}
}

func TestValidatePasswordStrength(t *testing.T) {
	if err := ValidatePasswordStrength("Abc@1234"); err != nil {
		t.Errorf("合法密码被拒: %v", err)
	}
	if err := ValidatePasswordStrength("abc"); err == nil {
		t.Error("过短密码未被拒绝")
	}
	if err := ValidatePasswordStrength(strings.Repeat("a", MaxPasswordLength+1)); err == nil {
		t.Error("超长密码未被拒绝")
	}
	// 中文按 rune 计数，8 个汉字应视为合法长度
	if err := ValidatePasswordStrength("密码密码密码密码"); err != nil {
		t.Errorf("中文密码长度按 rune 计数失败: %v", err)
	}
}

// ---------------------------------------------------------------- 令牌

func mustManager(t *testing.T) *TokenManager {
	t.Helper()
	m, err := NewTokenManager(strings.Repeat("k", 32), TokenIssuer, 15*time.Minute)
	if err != nil {
		t.Fatalf("构建 TokenManager 失败: %v", err)
	}
	return m
}

func TestTokenManager_IssueAndParse(t *testing.T) {
	m := mustManager(t)

	token, err := m.IssueAccess(42, "zhangsan")
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	claims, err := m.ParseAccess(token)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	id, err := claims.UserID()
	if err != nil || id != 42 {
		t.Fatalf("用户 ID 解析错误: id=%d err=%v", id, err)
	}
	if claims.Username != "zhangsan" {
		t.Fatalf("用户名不符: %s", claims.Username)
	}
	if claims.Use != TokenUseAccess {
		t.Fatalf("用途标记不符: %s", claims.Use)
	}
	if claims.ID == "" {
		t.Fatal("jti 为空")
	}
}

func TestTokenManager_ShortSecretRejected(t *testing.T) {
	if _, err := NewTokenManager("too-short", TokenIssuer, time.Minute); err == nil {
		t.Fatal("短密钥未被拒绝，HS256 抗爆破强度无法保证")
	}
}

func TestTokenManager_RejectsNonPositiveTTL(t *testing.T) {
	if _, err := NewTokenManager(strings.Repeat("k", 32), TokenIssuer, 0); err == nil {
		t.Fatal("TTL 为 0 未被拒绝，会签发出立即失效的令牌")
	}
}

// TestTokenManager_Expired 直接构造 exp 在过去的令牌。
//
// 不用「短 TTL + sleep」是因为 jwt 的时间声明只精确到秒，
// 短 TTL 会被截断，判定结果依赖签发时刻在秒内的位置，测试会偶发失败。
func TestTokenManager_Expired(t *testing.T) {
	m := mustManager(t)

	past := time.Now().Add(-2 * time.Minute)
	claims := AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    TokenIssuer,
			Subject:   "1",
			ID:        "test-jti",
			IssuedAt:  jwt.NewNumericDate(past),
			NotBefore: jwt.NewNumericDate(past),
			ExpiresAt: jwt.NewNumericDate(past.Add(time.Minute)), // 一分钟前就过期了
		},
		Use: TokenUseAccess,
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).
		SignedString([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatalf("构造令牌失败: %v", err)
	}

	if _, err := m.ParseAccess(token); err != ErrTokenExpired {
		t.Fatalf("过期令牌未返回 ErrTokenExpired: %v", err)
	}
}

func TestTokenManager_WrongSecret(t *testing.T) {
	m1 := mustManager(t)
	m2, _ := NewTokenManager(strings.Repeat("x", 32), TokenIssuer, time.Minute)

	token, _ := m1.IssueAccess(1, "u")
	if _, err := m2.ParseAccess(token); err == nil {
		t.Fatal("用错误密钥签发的令牌通过了校验")
	}
}

// TestParseAccess_RejectsAlgNone 是关键安全回归测试：
// 若 ParseAccess 未显式限定签名算法，攻击者可将 header 的 alg 改为 none
// 从而伪造任意身份的令牌。这个测试必须永久保留。
func TestParseAccess_RejectsAlgNone(t *testing.T) {
	m := mustManager(t)

	claims := jwt.MapClaims{
		"iss":  TokenIssuer,
		"sub":  "1",
		"use":  TokenUseAccess,
		"exp":  time.Now().Add(time.Hour).Unix(),
		"name": "admin",
	}
	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).
		SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("构造 alg=none 令牌失败: %v", err)
	}

	if _, err := m.ParseAccess(unsigned); err == nil {
		t.Fatal("alg=none 令牌通过了校验——存在 alg confusion 漏洞")
	}
}

func TestParseAccess_RejectsWrongIssuer(t *testing.T) {
	other, _ := NewTokenManager(strings.Repeat("k", 32), "another-service", time.Minute)
	token, _ := other.IssueAccess(1, "u")

	if _, err := mustManager(t).ParseAccess(token); err == nil {
		t.Fatal("其他签发者签发的令牌通过了校验")
	}
}

func TestParseAccess_RejectsWrongUse(t *testing.T) {
	m := mustManager(t)
	claims := AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    TokenIssuer,
			Subject:   "1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Use: "refresh", // 用途不符
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).
		SignedString([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatalf("构造令牌失败: %v", err)
	}
	if _, err := m.ParseAccess(token); err == nil {
		t.Fatal("用途不匹配的令牌通过了校验")
	}
}

// ---------------------------------------------------------------- 不透明令牌

func TestNewRefreshToken(t *testing.T) {
	plain, hash, err := NewRefreshToken()
	if err != nil {
		t.Fatalf("生成失败: %v", err)
	}
	if len(plain) < 40 {
		t.Fatalf("明文令牌过短: %d", len(plain))
	}
	if len(hash) != 64 {
		t.Fatalf("SHA-256 十六进制摘要应为 64 字符，实际 %d", len(hash))
	}
	if HashToken(plain) != hash {
		t.Fatal("HashToken 与生成时的摘要不一致")
	}
	// 两次生成必须不同
	plain2, _, _ := NewRefreshToken()
	if plain == plain2 {
		t.Fatal("两次生成的刷新令牌相同")
	}
}

func TestNewUUID(t *testing.T) {
	a, err := NewUUID()
	if err != nil {
		t.Fatalf("生成失败: %v", err)
	}
	if len(a) != 36 || strings.Count(a, "-") != 4 {
		t.Fatalf("UUID 格式非法: %s", a)
	}
	if a[14] != '4' {
		t.Fatalf("版本位不是 4: %s", a)
	}
	b, _ := NewUUID()
	if a == b {
		t.Fatal("两次生成的 UUID 相同")
	}
}

func TestSecureCompare(t *testing.T) {
	if !SecureCompare("abc123", "abc123") {
		t.Fatal("相同字符串被判为不同")
	}
	if SecureCompare("abc123", "abc124") || SecureCompare("abc", "abcd") {
		t.Fatal("不同字符串被判为相同")
	}
}

// ---------------------------------------------------------------- RBAC

// TestRolePermissionMatrix 锁定三角色权限矩阵。
// 这张表就是 P1 的验收标准，任何改动都会被这个测试拦下并要求显式确认。
func TestRolePermissionMatrix(t *testing.T) {
	type expect struct {
		perm  Permission
		admin bool
		asses bool
		audit bool
	}
	cases := []expect{
		{PermUserWrite, true, false, false},
		{PermRoleWrite, true, false, false},
		{PermAssetWrite, true, true, false},
		{PermDictWrite, true, true, false},
		{PermAssessWrite, true, true, false},
		{PermRemedWrite, true, true, false},
		{PermReportWrite, true, true, false},
		{PermAuditRead, true, false, true},
		{PermSystemWrite, true, false, false},
		{PermSystemRead, true, false, true},
		{PermUserRead, true, true, true},
		{PermAssetRead, true, true, true},
	}

	for _, c := range cases {
		sets := map[string]PermissionSet{
			RoleAdmin:    NewPermissionSet(PermissionsForRoles([]string{RoleAdmin})),
			RoleAssessor: NewPermissionSet(PermissionsForRoles([]string{RoleAssessor})),
			RoleAuditor:  NewPermissionSet(PermissionsForRoles([]string{RoleAuditor})),
		}
		wants := map[string]bool{
			RoleAdmin:    c.admin,
			RoleAssessor: c.asses,
			RoleAuditor:  c.audit,
		}
		for role, want := range wants {
			if got := sets[role].Has(c.perm); got != want {
				t.Errorf("权限 %s 对角色 %s：期望 %v，实际 %v", c.perm, role, want, got)
			}
		}
	}
}

func TestPermissionsForRoles_DedupAndOrder(t *testing.T) {
	// 重复角色不应产生重复权限
	a := PermissionsForRoles([]string{RoleAdmin, RoleAdmin})
	b := PermissionsForRoles([]string{RoleAdmin})
	if len(a) != len(b) {
		t.Fatalf("重复角色导致权限去重失败: %d vs %d", len(a), len(b))
	}

	// 顺序必须稳定
	c := PermissionsForRoles([]string{RoleAdmin})
	for i := range b {
		if b[i] != c[i] {
			t.Fatalf("权限顺序不稳定，第 %d 项不同", i)
		}
	}

	// 未知角色应返回空集而非 panic
	if got := PermissionsForRoles([]string{"no-such-role"}); len(got) != 0 {
		t.Fatalf("未知角色返回了权限: %v", got)
	}
	if got := PermissionsForRoles(nil); len(got) != 0 {
		t.Fatalf("空角色返回了权限: %v", got)
	}
}

func TestAuditorIsReadOnly(t *testing.T) {
	perms := PermissionsForRoles([]string{RoleAuditor})
	if len(perms) == 0 {
		t.Fatal("审计员没有任何权限")
	}
	for _, p := range perms {
		if strings.HasSuffix(string(p), ":write") {
			t.Fatalf("审计员持有写权限: %s", p)
		}
	}
}

func TestAssessorCannotManageUsers(t *testing.T) {
	set := NewPermissionSet(PermissionsForRoles([]string{RoleAssessor}))
	if set.Has(PermUserWrite) {
		t.Fatal("评估员不应具备用户管理权限")
	}
	if !set.Has(PermAssessWrite) {
		t.Fatal("评估员应具备评估写权限")
	}
}

func TestCheckPermissionRegistry(t *testing.T) {
	if problems := CheckPermissionRegistry(); len(problems) > 0 {
		t.Fatalf("权限注册表自检失败:\n  %s", strings.Join(problems, "\n  "))
	}
}

// ---------------------------------------------------------------- Cookie

func TestCookieAttributes(t *testing.T) {
	o := CookieOptions{Secure: true}

	at := o.Access("tok", 15*time.Minute)
	if !at.HttpOnly || !at.Secure || at.Path != "/" {
		t.Fatalf("访问令牌 Cookie 属性不符: %+v", at)
	}

	rt := o.Refresh("tok", 7*24*time.Hour)
	if !rt.HttpOnly {
		t.Fatal("刷新令牌必须 httpOnly")
	}
	// 刷新令牌必须限定路径，否则每个业务请求都会带上它
	if rt.Path != RefreshCookiePath {
		t.Fatalf("刷新令牌路径应为 %s，实际 %s", RefreshCookiePath, rt.Path)
	}

	cs := o.CSRF("tok", time.Hour)
	if cs.HttpOnly {
		t.Fatal("CSRF 令牌必须可被前端脚本读取（httpOnly=false）")
	}
}

func TestCookieClear(t *testing.T) {
	o := CookieOptions{}
	if c := o.ClearRefresh(); c.MaxAge != -1 || c.Path != RefreshCookiePath {
		t.Fatalf("清除刷新令牌 Cookie 属性不符: %+v", c)
	}
}
