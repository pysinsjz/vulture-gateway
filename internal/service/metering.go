package service

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/pysinsjz/vulture-gateway/internal/litellm"
	"github.com/pysinsjz/vulture-gateway/internal/pkg/idgen"
)

// LLM 用量窗口名（用于 ZSET key 与恢复头，llm-proxy.md §4）。
const (
	Window5h   = "5h"
	WindowWeek = "week"
)

// LLM 用量窗口大小（固定，非配置——属契约口径）。
const (
	Window5hSize   = 5 * time.Hour
	WindowWeekSize = 7 * 24 * time.Hour
)

// UsageWindow 描述一个滚动用量窗口（ADR-0008）。Cap<=0 视为不限（占位/未配额）。
type UsageWindow struct {
	Name string
	Size time.Duration
	Cap  int64 // Credit 上限（占位，待计费 C 域定数值）
}

// WindowReset 记录某触顶窗口的恢复时刻（Unix 秒）。
type WindowReset struct {
	Window    string
	ResetUnix int64
}

// PrecheckResult 是窗口预检结果。Exceeded=true 时 Resets 仅含触顶窗，RetryAfter 为距最早恢复的秒数。
type PrecheckResult struct {
	Exceeded   bool
	Resets     []WindowReset
	RetryAfter int64
}

// Pricing 是 token→Credit 折算（占位，待计费 C 域定 Model Price）。
type Pricing struct {
	PromptCreditPerToken     float64
	CompletionCreditPerToken float64
}

// CreditsFor 把一次 usage 折算为 Credit（向上取整，保证非零用量至少计 1）。
func (p Pricing) CreditsFor(u litellm.Usage) int64 {
	c := float64(u.PromptTokens)*p.PromptCreditPerToken + float64(u.CompletionTokens)*p.CompletionCreditPerToken
	credits := int64(math.Ceil(c))
	if credits <= 0 && (u.PromptTokens > 0 || u.CompletionTokens > 0) {
		credits = 1
	}
	return credits
}

// MeteringService 实现 LLM 用量计量与额度强制（ADR-0008，#26）：
// ZSET 双窗滑动计量（timestamp→credits）、乐观放行预检、按实/估算扣减。
//
// TODO(计费 C 域): 窗口 Cap 与 Pricing 均为占位注入，待计费域接入真实配额/定价。
type MeteringService struct {
	rdb     *redis.Client
	windows []UsageWindow
	pricing Pricing
}

// NewMeteringService 构造计量服务。
func NewMeteringService(rdb *redis.Client, windows []UsageWindow, pricing Pricing) *MeteringService {
	return &MeteringService{rdb: rdb, windows: windows, pricing: pricing}
}

// usageKey 与窗口隔离：usage:{userUUID}:{window}。
func usageKey(userUUID, window string) string {
	return fmt.Sprintf("usage:%s:%s", userUUID, window)
}

// Precheck 对所有有配额的窗口做乐观预检：任一窗已触顶（滚动求和 >= Cap）即 Exceeded。
// 恢复时刻 = 该窗最早一笔事件滑出窗口的时刻（oldest_score + Size），RetryAfter 取最早者。
func (m *MeteringService) Precheck(ctx context.Context, userUUID string, now time.Time) (*PrecheckResult, error) {
	res := &PrecheckResult{}
	earliest := int64(math.MaxInt64)
	for _, w := range m.windows {
		if w.Cap <= 0 {
			continue
		}
		sum, oldest, err := m.windowSum(ctx, userUUID, w, now)
		if err != nil {
			return nil, err
		}
		if sum >= w.Cap {
			reset := oldest + int64(w.Size.Seconds())
			res.Exceeded = true
			res.Resets = append(res.Resets, WindowReset{Window: w.Name, ResetUnix: reset})
			if reset < earliest {
				earliest = reset
			}
		}
	}
	if res.Exceeded {
		if ra := earliest - now.Unix(); ra > 0 {
			res.RetryAfter = ra
		}
	}
	return res, nil
}

// Record 把一次用量折算为 Credit 并对所有窗口原子扣减（ZADD 唯一成员，并发不丢不重）。
// 零 Credit（无 usage 的硬错误）不写入。
func (m *MeteringService) Record(ctx context.Context, userUUID string, usage litellm.Usage, now time.Time) error {
	credits := m.pricing.CreditsFor(usage)
	if credits <= 0 {
		return nil
	}
	member := fmt.Sprintf("%d:%s", credits, idgen.New("ev"))
	score := float64(now.Unix())
	for _, w := range m.windows {
		k := usageKey(userUUID, w.Name)
		if err := m.rdb.ZAdd(ctx, k, redis.Z{Score: score, Member: member}).Err(); err != nil {
			return fmt.Errorf("计量扣减失败(%s): %w", w.Name, err)
		}
		// 自清理：窗口大小 + 1h 宽限后整 key 过期，避免长期不活跃用户残留。
		m.rdb.Expire(ctx, k, w.Size+time.Hour)
	}
	return nil
}

// windowSum 修剪滑出窗口的事件后，返回窗内 Credit 总和与最早一笔的时刻（Unix 秒）。
func (m *MeteringService) windowSum(ctx context.Context, userUUID string, w UsageWindow, now time.Time) (sum int64, oldest int64, err error) {
	k := usageKey(userUUID, w.Name)
	cutoff := now.Add(-w.Size).Unix()
	// 修剪 score < cutoff 的滑出事件（cutoff 当刻仍在窗内）。
	if err := m.rdb.ZRemRangeByScore(ctx, k, "-inf", fmt.Sprintf("(%d", cutoff)).Err(); err != nil {
		return 0, 0, fmt.Errorf("修剪用量窗口失败(%s): %w", w.Name, err)
	}
	members, err := m.rdb.ZRangeByScoreWithScores(ctx, k, &redis.ZRangeBy{
		Min: strconv.FormatInt(cutoff, 10),
		Max: "+inf",
	}).Result()
	if err != nil {
		return 0, 0, fmt.Errorf("读取用量窗口失败(%s): %w", w.Name, err)
	}
	for _, z := range members {
		member, _ := z.Member.(string)
		sum += creditsFromMember(member)
		ts := int64(z.Score)
		if oldest == 0 || ts < oldest {
			oldest = ts
		}
	}
	return sum, oldest, nil
}

// creditsFromMember 从 ZSET 成员 "<credits>:<nonce>" 取 credits。
func creditsFromMember(member string) int64 {
	i := strings.IndexByte(member, ':')
	if i < 0 {
		return 0
	}
	c, err := strconv.ParseInt(member[:i], 10, 64)
	if err != nil {
		return 0
	}
	return c
}

// EstimateUsage 占位估算：按字符数÷4 估 token（usage 缺失/流中断时兜底，#26）。
//
// TODO(计费 C 域): 待真实 tokenizer 接入替换此启发式。
func EstimateUsage(promptChars, completionChars int) litellm.Usage {
	p := estTokens(promptChars)
	c := estTokens(completionChars)
	return litellm.Usage{PromptTokens: p, CompletionTokens: c, TotalTokens: p + c}
}

func estTokens(chars int) int64 {
	if chars <= 0 {
		return 0
	}
	return int64(math.Ceil(float64(chars) / 4.0))
}

// PromptChars 从请求体估算 prompt 文本字符数：累加各 message 的 content 长度（占位）。
// content 可为字符串或多模态数组，统一按其 JSON 原文长度计（粗估，待真实 tokenizer 替换）。
func PromptChars(reqBody []byte) int {
	var req struct {
		Messages []struct {
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(reqBody, &req); err != nil {
		return 0
	}
	total := 0
	for _, msg := range req.Messages {
		s := strings.Trim(string(msg.Content), `"`)
		total += len(s)
	}
	return total
}
