package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/pysinsjz/vulture-gateway/internal/auth"
	"github.com/pysinsjz/vulture-gateway/internal/dao"
)

// ErrDeviceNotFound 表示目标 Device 不存在或不属于当前 User。
var ErrDeviceNotFound = errors.New("device not found")

// DeviceView 是设备列表的对外视图。
type DeviceView struct {
	DeviceID     string `json:"device_id"`
	Name         string `json:"name"`
	OS           string `json:"os"`
	AppVersion   string `json:"app_version"`
	CreatedAt    int64  `json:"created_at"`
	LastActiveAt int64  `json:"last_active_at"`
	Current      bool   `json:"current"`
}

// DeviceService 处理登出与 Device 管理。吊销动作 = bump token_version（即时吊销，ADR-0010）
// + 作废该 Device 的 refresh。
type DeviceService struct {
	tvs       *auth.TokenVersionStore
	devices   dao.DeviceRepository
	refreshes dao.RefreshTokenRepository
}

// NewDeviceService 构造服务。
func NewDeviceService(tvs *auth.TokenVersionStore, devices dao.DeviceRepository, refreshes dao.RefreshTokenRepository) *DeviceService {
	return &DeviceService{tvs: tvs, devices: devices, refreshes: refreshes}
}

// LogoutByDevice 吊销指定 Device（Bearer 路）。
func (s *DeviceService) LogoutByDevice(ctx context.Context, deviceUUID string) error {
	return s.revoke(ctx, deviceUUID)
}

// LogoutByRefreshToken 按 refresh token 兜底吊销其绑定的 Device（access 已失效路）。
// RT 未知时静默成功（登出幂等，不泄露 RT 是否存在）。
func (s *DeviceService) LogoutByRefreshToken(ctx context.Context, refreshPlain string) error {
	if refreshPlain == "" {
		return nil
	}
	row, found, err := s.refreshes.FindByHash(ctx, hashToken(refreshPlain))
	if err != nil {
		return fmt.Errorf("查询 refresh token 失败: %w", err)
	}
	if !found {
		return nil
	}
	return s.revoke(ctx, row.DeviceUUID)
}

// ListDevices 列出 User 的全部 Device，标记当前设备。
func (s *DeviceService) ListDevices(ctx context.Context, userUUID, currentDeviceUUID string) ([]DeviceView, error) {
	devices, err := s.devices.ListByUser(ctx, userUUID)
	if err != nil {
		return nil, fmt.Errorf("列出 Device 失败: %w", err)
	}
	views := make([]DeviceView, 0, len(devices))
	for _, d := range devices {
		views = append(views, DeviceView{
			DeviceID:     d.UUID,
			Name:         d.Name,
			OS:           d.OS,
			AppVersion:   d.AppVersion,
			CreatedAt:    d.CreatedAt,
			LastActiveAt: d.LastActiveAt,
			Current:      d.UUID == currentDeviceUUID,
		})
	}
	return views, nil
}

// RevokeDevice 吊销指定 Device（需归属当前 User）。非本人或不存在返回 ErrDeviceNotFound。
func (s *DeviceService) RevokeDevice(ctx context.Context, userUUID, targetDeviceUUID string) error {
	device, found, err := s.devices.GetByUUID(ctx, targetDeviceUUID)
	if err != nil {
		return fmt.Errorf("查询 Device 失败: %w", err)
	}
	if !found || device.UserUUID != userUUID {
		return ErrDeviceNotFound
	}
	return s.revoke(ctx, targetDeviceUUID)
}

// revoke bump token_version（即时杀在途 access）+ 作废该 Device 的 refresh。
func (s *DeviceService) revoke(ctx context.Context, deviceUUID string) error {
	if err := s.refreshes.RevokeByDevice(ctx, deviceUUID); err != nil {
		return fmt.Errorf("作废 refresh 失败: %w", err)
	}
	if _, err := s.tvs.Bump(ctx, deviceUUID); err != nil {
		return fmt.Errorf("bump token_version 失败: %w", err)
	}
	return nil
}
