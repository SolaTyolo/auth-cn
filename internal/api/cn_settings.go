package api

import "github.com/supabase/auth/internal/conf"

// CNExternalProviderSettings carries China-specific OAuth provider flags for /settings.
type CNExternalProviderSettings struct {
	Line       bool `json:"line"`
	Douyin     bool `json:"douyin"`
	Wechat     bool `json:"wechat"`
	WechatWork bool `json:"wechat_work"`
}

func cnExternalProviderSettingsFromConfig(config *conf.GlobalConfiguration) CNExternalProviderSettings {
	return CNExternalProviderSettings{
		Line:       config.External.Line.Enabled,
		Douyin:     config.External.Douyin.Enabled,
		Wechat:     config.External.Wechat.Enabled,
		WechatWork: config.External.WechatWork.Enabled,
	}
}
