// Package service 是业务逻辑层。
package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/pysinsjz/vulture-gateway/internal/auth"
	"github.com/pysinsjz/vulture-gateway/internal/dao"
	"github.com/pysinsjz/vulture-gateway/internal/model"
	"github.com/pysinsjz/vulture-gateway/internal/pkg/idgen"
)

// ErrInvalidGrant 表示 GW_CODE/PKCE/redirect_uri 任一校验不通过，统一对应 RFC 6749 的 invalid_grant。
var ErrInvalidGrant = errors.New("invalid_grant")

// 首次签发的 token_version 基线。
const initialTokenVersion int64 = 1

// DeviceMeta 桌面端上报的设备元信息。
type DeviceMeta struct {
	Name       string
	OS         string
	AppVersion string
}

// ExchangeCodeInput 是 authorization_code 换取令牌的入参。
type ExchangeCodeInput struct {
	Code         string
	CodeVerifier string
	RedirectURI  string
	Device       DeviceMeta
}

// TokenResult 是令牌交换的结果。
type TokenResult struct {
	AccessToken  string
	RefreshToken string
	DeviceID     string
	ExpiresIn    int
}

// OAuthService 编排 OAuth 令牌交换。
type OAuthService struct {
	txer        dao.Transactor
	devices     dao.DeviceRepository
	refreshes   dao.RefreshTokenRepository
	gwcodes     *auth.GWCodeStore
	tvs         *auth.TokenVersionStore
	replays     *auth.RefreshReplayStore
	locker      *auth.Locker
	signer      *auth.Signer
	refreshTTL  time.Duration
	graceWindow time.Duration
}

// NewOAuthService 构造服务。
func NewOAuthService(
	txer dao.Transactor,
	devices dao.DeviceRepository,
	refreshes dao.RefreshTokenRepository,
	gwcodes *auth.GWCodeStore,
	tvs *auth.TokenVersionStore,
	replays *auth.RefreshReplayStore,
	locker *auth.Locker,
	signer *auth.Signer,
	refreshTTL time.Duration,
	graceWindow time.Duration,
) *OAuthService {
	return &OAuthService{
		txer:        txer,
		devices:     devices,
		refreshes:   refreshes,
		gwcodes:     gwcodes,
		tvs:         tvs,
		replays:     replays,
		locker:      locker,
		signer:      signer,
		refreshTTL:  refreshTTL,
		graceWindow: graceWindow,
	}
}

// ExchangeAuthorizationCode 用 GW_CODE 换取 access JWT + refresh token，并创建一台 Device。
// 校验类失败返回 ErrInvalidGrant；系统类失败返回其它 error（由调用方映射 5xx）。
func (s *OAuthService) ExchangeAuthorizationCode(ctx context.Context, in ExchangeCodeInput) (*TokenResult, error) {
	// 1. 消费 GW_CODE（单次使用：取出即删，过期/复用自然 found=false）。
	gw, found, err := s.gwcodes.Consume(ctx, in.Code)
	if err != nil {
		return nil, fmt.Errorf("消费 GW_CODE 失败: %w", err)
	}
	if !found {
		return nil, ErrInvalidGrant
	}

	// 2. redirect_uri 必须与签发时一致。
	if gw.RedirectURI != in.RedirectURI {
		return nil, ErrInvalidGrant
	}

	// 3. PKCE：code_verifier 经 S256 应匹配暂存的 challenge。
	if !auth.VerifyS256(in.CodeVerifier, gw.CodeChallenge) {
		return nil, ErrInvalidGrant
	}

	now := time.Now().Unix()
	deviceID := idgen.New("dev")
	device := &model.Device{
		UUID:         deviceID,
		UserUUID:     gw.UserUUID,
		Name:         in.Device.Name,
		OS:           in.Device.OS,
		AppVersion:   in.Device.AppVersion,
		LastActiveAt: now,
	}

	refreshPlain := idgen.New("rt")
	rt := &model.RefreshToken{
		TokenHash:  hashToken(refreshPlain),
		FamilyID:   idgen.New("rtf"),
		DeviceUUID: deviceID,
		UserUUID:   gw.UserUUID,
		LastUsedAt: now,
		ExpiresAt:  now + int64(s.refreshTTL.Seconds()),
	}

	// 4. 原子创建 Device + refresh token。
	if err := s.txer.WithinTx(ctx, func(ctx context.Context) error {
		if err := s.devices.Create(ctx, device); err != nil {
			return err
		}
		return s.refreshes.Create(ctx, rt)
	}); err != nil {
		return nil, fmt.Errorf("创建 Device/refresh 失败: %w", err)
	}

	// 5. Redis 写初始 token_version（事务成功后执行，ADR-0010）。
	if err := s.tvs.Set(ctx, deviceID, initialTokenVersion); err != nil {
		return nil, fmt.Errorf("写入 token_version 失败: %w", err)
	}

	// 6. 签发 access JWT。
	access, err := s.signer.Issue(gw.UserUUID, deviceID, initialTokenVersion)
	if err != nil {
		return nil, fmt.Errorf("签发 access JWT 失败: %w", err)
	}

	return &TokenResult{
		AccessToken:  access,
		RefreshToken: refreshPlain,
		DeviceID:     deviceID,
		ExpiresIn:    int(s.signer.TTL().Seconds()),
	}, nil
}

// errAlreadyUsed 是轮换时发现 token 已被并发翻转的内部哨兵（锁串行下通常不发生）。
var errAlreadyUsed = errors.New("refresh token already used")

const refreshLockTTL = 10 * time.Second

// ExchangeRefreshToken 用 refresh token 换取新 access + 轮换后的新 refresh（A2，#13）。
// 校验类失败返回 ErrInvalidGrant（调用方映射 401）；系统类失败返回其它 error。
//
// 同一 RT 的并发刷新由 Redis 锁串行化：胜者轮换并缓存令牌对，其余在宽限窗内重放同一对。
func (s *OAuthService) ExchangeRefreshToken(ctx context.Context, refreshPlain string) (*TokenResult, error) {
	if refreshPlain == "" {
		return nil, ErrInvalidGrant
	}
	hash := hashToken(refreshPlain)

	release, err := s.acquireRefreshLock(ctx, hash)
	if err != nil {
		return nil, err
	}
	defer release()

	row, found, err := s.refreshes.FindByHash(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("查询 refresh token 失败: %w", err)
	}
	if !found || row.Revoked {
		return nil, ErrInvalidGrant
	}
	if row.ExpiresAt < time.Now().Unix() {
		return nil, ErrInvalidGrant // 空闲超 60 天，已过期
	}

	// 已被轮换：宽限窗内重放同一对，窗外判盗。
	if row.Used {
		return s.replayOrTheft(ctx, hash, row)
	}

	return s.rotate(ctx, hash, row)
}

// rotate 正常轮换：标记旧 RT 已用、建新 RT、签新 access，并缓存令牌对供宽限窗重放。
func (s *OAuthService) rotate(ctx context.Context, oldHash string, row *model.RefreshToken) (*TokenResult, error) {
	version, exists, err := s.tvs.Current(ctx, row.DeviceUUID)
	if err != nil {
		return nil, fmt.Errorf("读取 token_version 失败: %w", err)
	}
	if !exists {
		return nil, ErrInvalidGrant // Device 已被吊销
	}

	now := time.Now()
	newPlain := idgen.New("rt")
	newRow := &model.RefreshToken{
		TokenHash:  hashToken(newPlain),
		FamilyID:   row.FamilyID,
		DeviceUUID: row.DeviceUUID,
		UserUUID:   row.UserUUID,
		LastUsedAt: now.Unix(),
		ExpiresAt:  now.Add(s.refreshTTL).Unix(), // 滑动续期
	}

	if err := s.txer.WithinTx(ctx, func(ctx context.Context) error {
		flipped, err := s.refreshes.MarkUsedIfUnused(ctx, oldHash)
		if err != nil {
			return err
		}
		if !flipped {
			return errAlreadyUsed
		}
		if err := s.refreshes.Create(ctx, newRow); err != nil {
			return err
		}
		// last_active_at 随刷新更新（#14）。
		return s.devices.UpdateLastActive(ctx, row.DeviceUUID, now.Unix())
	}); err != nil {
		if errors.Is(err, errAlreadyUsed) {
			// 并发已轮换（锁失效兜底）：退回重放。
			if pair, ok, gerr := s.replays.Get(ctx, oldHash); gerr == nil && ok {
				return s.pairResult(pair, row.DeviceUUID), nil
			}
			return nil, ErrInvalidGrant
		}
		return nil, fmt.Errorf("轮换 refresh token 失败: %w", err)
	}

	access, err := s.signer.Issue(row.UserUUID, row.DeviceUUID, version)
	if err != nil {
		return nil, fmt.Errorf("签发 access JWT 失败: %w", err)
	}

	pair := auth.RefreshPair{AccessToken: access, RefreshToken: newPlain}
	if err := s.replays.Save(ctx, oldHash, pair); err != nil {
		return nil, fmt.Errorf("缓存重放对失败: %w", err)
	}
	return s.pairResult(pair, row.DeviceUUID), nil
}

// replayOrTheft 处理已被轮换的旧 RT：宽限窗内重放同一对，窗外判盗作废家族。
func (s *OAuthService) replayOrTheft(ctx context.Context, oldHash string, row *model.RefreshToken) (*TokenResult, error) {
	pair, ok, err := s.replays.Get(ctx, oldHash)
	if err != nil {
		return nil, fmt.Errorf("读取重放对失败: %w", err)
	}
	if ok {
		return s.pairResult(pair, row.DeviceUUID), nil
	}

	// 窗外出示已被取代的 RT → 判盗：作废整个家族 + bump token_version（即时杀在途 access）。
	if err := s.refreshes.RevokeFamily(ctx, row.FamilyID); err != nil {
		return nil, fmt.Errorf("作废 refresh 家族失败: %w", err)
	}
	if _, err := s.tvs.Bump(ctx, row.DeviceUUID); err != nil {
		return nil, fmt.Errorf("bump token_version 失败: %w", err)
	}
	return nil, ErrInvalidGrant
}

func (s *OAuthService) pairResult(pair auth.RefreshPair, deviceID string) *TokenResult {
	return &TokenResult{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		DeviceID:     deviceID,
		ExpiresIn:    int(s.signer.TTL().Seconds()),
	}
}

// acquireRefreshLock 获取同一 RT 的刷新锁（带短重试等待），返回释放函数。
func (s *OAuthService) acquireRefreshLock(ctx context.Context, hash string) (func(), error) {
	key := "oauth:refresh:lock:" + hash
	deadline := time.Now().Add(2 * time.Second)
	for {
		ok, err := s.locker.Acquire(ctx, key, refreshLockTTL)
		if err != nil {
			return nil, err
		}
		if ok {
			return func() { s.locker.Release(ctx, key) }, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("获取 refresh 锁超时")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// hashToken 返回 refresh token 明文的 sha256 十六进制（仅存哈希，不存明文）。
func hashToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}
