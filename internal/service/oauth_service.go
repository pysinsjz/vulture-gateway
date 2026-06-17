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
	txer       dao.Transactor
	devices    dao.DeviceRepository
	refreshes  dao.RefreshTokenRepository
	gwcodes    *auth.GWCodeStore
	tvs        *auth.TokenVersionStore
	signer     *auth.Signer
	refreshTTL time.Duration
}

// NewOAuthService 构造服务。
func NewOAuthService(
	txer dao.Transactor,
	devices dao.DeviceRepository,
	refreshes dao.RefreshTokenRepository,
	gwcodes *auth.GWCodeStore,
	tvs *auth.TokenVersionStore,
	signer *auth.Signer,
	refreshTTL time.Duration,
) *OAuthService {
	return &OAuthService{
		txer:       txer,
		devices:    devices,
		refreshes:  refreshes,
		gwcodes:    gwcodes,
		tvs:        tvs,
		signer:     signer,
		refreshTTL: refreshTTL,
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

// hashToken 返回 refresh token 明文的 sha256 十六进制（仅存哈希，不存明文）。
func hashToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}
