package sms_provider

import "github.com/supabase/auth/internal/conf"

type CNSMSFactory func(config conf.GlobalConfiguration) (SmsProvider, error)

var cnSMSProviders = map[string]CNSMSFactory{}

func RegisterCNSMSProvider(name string, factory CNSMSFactory) {
	cnSMSProviders[name] = factory
}

func ResolveCNSMSProvider(config conf.GlobalConfiguration, name string) (SmsProvider, error, bool) {
	factory, ok := cnSMSProviders[name]
	if !ok {
		return nil, nil, false
	}

	p, err := factory(config)
	return p, err, true
}
