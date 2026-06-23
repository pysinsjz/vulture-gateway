package signin

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/pysinsjz/vulture-gateway/internal/auth"
	"github.com/pysinsjz/vulture-gateway/internal/model"
)

// ---- fakes ----

type fakeIdentityRepo struct {
	byKey   map[string]*model.Identity
	created []*model.Identity
}

func newFakeIdentityRepo() *fakeIdentityRepo {
	return &fakeIdentityRepo{byKey: map[string]*model.Identity{}}
}

func idKey(typ, identifier string) string { return typ + "|" + identifier }

func (r *fakeIdentityRepo) FindByTypeIdentifier(_ context.Context, typ, identifier string) (*model.Identity, bool, error) {
	if id, ok := r.byKey[idKey(typ, identifier)]; ok {
		cp := *id
		return &cp, true, nil
	}
	return nil, false, nil
}

func (r *fakeIdentityRepo) Create(_ context.Context, identity *model.Identity) error {
	r.byKey[idKey(identity.Type, identity.Identifier)] = identity
	r.created = append(r.created, identity)
	return nil
}

type fakeUserRepo struct {
	created []*model.User
	seq     int64
}

func (r *fakeUserRepo) Create(_ context.Context, u *model.User) error {
	r.seq++
	u.ID = r.seq
	r.created = append(r.created, u)
	return nil
}

func (r *fakeUserRepo) ResolveOrCreateBySubject(_ context.Context, subject string) (*model.User, error) {
	return &model.User{UUID: "usr_" + subject, Subject: subject}, nil
}

type fakeTransactor struct{}

func (fakeTransactor) WithinTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

// ---- harness ----

type deps struct {
	identities *fakeIdentityRepo
	users      *fakeUserRepo
	tx         fakeTransactor
	otp        *auth.OTPStore
	limiter    *auth.RateLimiter
	hasher     auth.PasswordHasher
	rsa        *auth.RSADecryptor
	pub        *rsa.PublicKey
	mr         *miniredis.Miniredis
}

func newDeps(t *testing.T) *deps {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("启动 miniredis 失败: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 密钥失败: %v", err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	rsaDec, err := auth.NewRSADecryptor(privPEM)
	if err != nil {
		t.Fatalf("构造 RSA 解密器失败: %v", err)
	}

	return &deps{
		identities: newFakeIdentityRepo(),
		users:      &fakeUserRepo{},
		otp:        auth.NewOTPStore(rdb, 5*time.Minute, 60*time.Second, 5, ""),
		limiter: auth.NewRateLimiter(rdb, auth.RateLimitConfig{
			LoginMaxFailures: 5, LoginLockWindow: 15 * time.Minute, SendMax: 3, SendWindow: 10 * time.Minute,
		}),
		hasher: auth.NewBcryptHasher(4), // 测试用低 cost 提速
		rsa:    rsaDec,
		pub:    &key.PublicKey,
		mr:     mr,
	}
}

func (d *deps) encrypt(t *testing.T, plain string) string {
	t.Helper()
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, d.pub, []byte(plain), nil)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	return base64.StdEncoding.EncodeToString(ct)
}

// seedPasswordIdentity 预置一条已设密码的 email 身份。
func (d *deps) seedPasswordIdentity(t *testing.T, email, userUUID, password string) {
	t.Helper()
	hash, err := d.hasher.Hash(password)
	if err != nil {
		t.Fatalf("hash 失败: %v", err)
	}
	d.identities.byKey[idKey(model.IdentityTypeEmail, email)] = &model.Identity{
		UUID: "idn_seed", UserUUID: userUUID, Type: model.IdentityTypeEmail, Identifier: email, Secret: hash,
	}
}

// ---- password 方式 ----

func TestPasswordMethod_Success(t *testing.T) {
	d := newDeps(t)
	d.seedPasswordIdentity(t, "a@b.com", "usr_42", "correct horse")
	m := NewPasswordMethod(d.identities, d.hasher, d.rsa, d.limiter)

	subject, err := m.Verify(context.Background(), VerifyInput{
		Identifier: "a@b.com", Credential: d.encrypt(t, "correct horse"), IP: "1.2.3.4",
	})
	if err != nil {
		t.Fatalf("正确密码应通过: %v", err)
	}
	if subject != "usr_42" {
		t.Errorf("subject 应为 usr_42, 实际 %q", subject)
	}
}

func TestPasswordMethod_PhoneIdentifier(t *testing.T) {
	d := newDeps(t)
	hash, _ := d.hasher.Hash("phone-pass")
	d.identities.byKey[idKey(model.IdentityTypePhone, "13800000000")] = &model.Identity{
		UUID: "idn_p", UserUUID: "usr_phone", Type: model.IdentityTypePhone, Identifier: "13800000000", Secret: hash,
	}
	m := NewPasswordMethod(d.identities, d.hasher, d.rsa, d.limiter)

	subject, err := m.Verify(context.Background(), VerifyInput{
		Identifier: "13800000000", Credential: d.encrypt(t, "phone-pass"), IP: "1.2.3.4",
	})
	if err != nil || subject != "usr_phone" {
		t.Errorf("手机号密码登录应通过返回 usr_phone, got subject=%q err=%v", subject, err)
	}
}

func TestPasswordMethod_Failures(t *testing.T) {
	cases := []struct {
		name       string
		setup      func(t *testing.T, d *deps)
		credential func(t *testing.T, d *deps) string
		wantErr    error
	}{
		{
			name:       "密码错误",
			setup:      func(t *testing.T, d *deps) { d.seedPasswordIdentity(t, "a@b.com", "usr_1", "right") },
			credential: func(t *testing.T, d *deps) string { return d.encrypt(t, "wrong") },
			wantErr:    ErrInvalidCredentials,
		},
		{
			name:       "账号不存在",
			setup:      func(t *testing.T, d *deps) {},
			credential: func(t *testing.T, d *deps) string { return d.encrypt(t, "whatever") },
			wantErr:    ErrInvalidCredentials,
		},
		{
			name: "未设密码（仅验证码账号）",
			setup: func(t *testing.T, d *deps) {
				d.identities.byKey[idKey(model.IdentityTypeEmail, "a@b.com")] = &model.Identity{
					UUID: "idn_x", UserUUID: "usr_1", Type: model.IdentityTypeEmail, Identifier: "a@b.com", Secret: "",
				}
			},
			credential: func(t *testing.T, d *deps) string { return d.encrypt(t, "whatever") },
			wantErr:    ErrInvalidCredentials,
		},
		{
			name:       "RSA 密文非法",
			setup:      func(t *testing.T, d *deps) { d.seedPasswordIdentity(t, "a@b.com", "usr_1", "right") },
			credential: func(t *testing.T, d *deps) string { return "@@@not-base64@@@" },
			wantErr:    ErrInvalidCredentials,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newDeps(t)
			c.setup(t, d)
			m := NewPasswordMethod(d.identities, d.hasher, d.rsa, d.limiter)
			_, err := m.Verify(context.Background(), VerifyInput{
				Identifier: "a@b.com", Credential: c.credential(t, d), IP: "1.2.3.4",
			})
			if !errors.Is(err, c.wantErr) {
				t.Errorf("err = %v, 期望 %v", err, c.wantErr)
			}
		})
	}
}

func TestPasswordMethod_LockAfterMaxFailures(t *testing.T) {
	d := newDeps(t)
	d.seedPasswordIdentity(t, "a@b.com", "usr_1", "right")
	m := NewPasswordMethod(d.identities, d.hasher, d.rsa, d.limiter)
	ctx := context.Background()
	wrong := d.encrypt(t, "wrong")

	// 前 4 次失败：凭据错。
	for i := 0; i < 4; i++ {
		if _, err := m.Verify(ctx, VerifyInput{Identifier: "a@b.com", Credential: wrong, IP: "9.9.9.9"}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("第 %d 次应凭据错, got %v", i+1, err)
		}
	}
	// 第 5 次失败触发锁定。
	if _, err := m.Verify(ctx, VerifyInput{Identifier: "a@b.com", Credential: wrong, IP: "9.9.9.9"}); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("第 5 次应锁定, got %v", err)
	}
	// 锁定后即便密码正确也拒。
	if _, err := m.Verify(ctx, VerifyInput{Identifier: "a@b.com", Credential: d.encrypt(t, "right"), IP: "9.9.9.9"}); !errors.Is(err, ErrAccountLocked) {
		t.Errorf("锁定后正确密码也应拒, got %v", err)
	}
}

// ---- 验证码方式（登录即注册）----

func TestCodeMethod_ExistingIdentity(t *testing.T) {
	d := newDeps(t)
	d.identities.byKey[idKey(model.IdentityTypeEmail, "x@y.com")] = &model.Identity{
		UUID: "idn_e", UserUUID: "usr_existing", Type: model.IdentityTypeEmail, Identifier: "x@y.com",
	}
	m := NewEmailCodeMethod(d.otp, d.identities, d.users, d.tx)
	ctx := context.Background()

	code, _ := d.otp.Issue(ctx, "x@y.com")
	subject, err := m.Verify(ctx, VerifyInput{Identifier: "x@y.com", Credential: code, IP: "1.1.1.1"})
	if err != nil {
		t.Fatalf("正确验证码应通过: %v", err)
	}
	if subject != "usr_existing" {
		t.Errorf("应解析既有 User usr_existing, 实际 %q", subject)
	}
	if len(d.users.created) != 0 {
		t.Error("既有身份不应新建 User")
	}
}

func TestCodeMethod_LoginIsRegistration(t *testing.T) {
	d := newDeps(t)
	m := NewEmailCodeMethod(d.otp, d.identities, d.users, d.tx)
	ctx := context.Background()

	code, _ := d.otp.Issue(ctx, "new@y.com")
	subject, err := m.Verify(ctx, VerifyInput{Identifier: "new@y.com", Credential: code, IP: "1.1.1.1"})
	if err != nil {
		t.Fatalf("验证码登录即注册应通过: %v", err)
	}
	// 命门：建号且 subject == 新 User.uuid（本地锚），下游 ResolveOrCreateBySubject 据此幂等命中。
	if len(d.users.created) != 1 {
		t.Fatalf("应新建 1 个 User, 实际 %d", len(d.users.created))
	}
	u := d.users.created[0]
	if u.Subject != u.UUID {
		t.Errorf("本地用户 subject 应等于 uuid: subject=%q uuid=%q", u.Subject, u.UUID)
	}
	if subject != u.UUID {
		t.Errorf("返回 subject 应为新 User.uuid %q, 实际 %q", u.UUID, subject)
	}
	// 同步建了 Identity，secret 留空（仅验证码登录）。
	if len(d.identities.created) != 1 {
		t.Fatalf("应新建 1 条 Identity, 实际 %d", len(d.identities.created))
	}
	if id := d.identities.created[0]; id.Secret != "" || id.UserUUID != u.UUID || id.Type != model.IdentityTypeEmail {
		t.Errorf("新建 Identity 不符: %+v", id)
	}
}

func TestCodeMethod_WrongCode(t *testing.T) {
	d := newDeps(t)
	m := NewSmsCodeMethod(d.otp, d.identities, d.users, d.tx)
	ctx := context.Background()

	_, _ = d.otp.Issue(ctx, "13800000000")
	_, err := m.Verify(ctx, VerifyInput{Identifier: "13800000000", Credential: "000000", IP: "1.1.1.1"})
	if !errors.Is(err, ErrInvalidCode) {
		t.Errorf("错误验证码应 ErrInvalidCode, got %v", err)
	}
	if len(d.users.created) != 0 {
		t.Error("验证码错误不应建号")
	}
}

func TestSmsCodeMethod_TypeIsPhone(t *testing.T) {
	d := newDeps(t)
	m := NewSmsCodeMethod(d.otp, d.identities, d.users, d.tx)
	ctx := context.Background()
	code, _ := d.otp.Issue(ctx, "13900000000")
	if _, err := m.Verify(ctx, VerifyInput{Identifier: "13900000000", Credential: code, IP: "1.1.1.1"}); err != nil {
		t.Fatalf("应通过: %v", err)
	}
	if id := d.identities.created[0]; id.Type != model.IdentityTypePhone {
		t.Errorf("sms_code 建的身份类型应为 phone, 实际 %q", id.Type)
	}
}

// ---- registry / directBase ----

func TestRegistry_ListOrderAndGet(t *testing.T) {
	d := newDeps(t)
	pw := NewPasswordMethod(d.identities, d.hasher, d.rsa, d.limiter)
	ec := NewEmailCodeMethod(d.otp, d.identities, d.users, d.tx)
	reg := NewRegistry(pw, ec)

	list := reg.List()
	if len(list) != 2 || list[0].Name() != "password" || list[1].Name() != "email_code" {
		t.Errorf("List 顺序应为 [password, email_code], 实际 %v", names(list))
	}
	if _, ok := reg.Get("password"); !ok {
		t.Error("应能 Get password")
	}
	if _, ok := reg.Get("nope"); ok {
		t.Error("未注册方式应 Get 失败")
	}
}

func TestDirectMethod_RejectsRedirectOps(t *testing.T) {
	d := newDeps(t)
	m := NewPasswordMethod(d.identities, d.hasher, d.rsa, d.limiter)
	if m.Kind() != KindDirect {
		t.Error("password 应为 Direct")
	}
	if _, err := m.AuthorizeURL("s", "n"); !errors.Is(err, ErrNotRedirect) {
		t.Errorf("Direct.AuthorizeURL 应 ErrNotRedirect, got %v", err)
	}
	if _, err := m.Exchange(context.Background(), "c", "n"); !errors.Is(err, ErrNotRedirect) {
		t.Errorf("Direct.Exchange 应 ErrNotRedirect, got %v", err)
	}
}

func names(ms []SigninMethod) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.Name()
	}
	return out
}

// nil2t 让 setup 闭包能在无 *testing.T 时调用 seed（seed 内部仅在 hash 失败时 Fatal，
// 测试用低 cost 不会失败）。仅用于表驱动 setup 简化。
func nil2t() *testing.T { return &testing.T{} }
