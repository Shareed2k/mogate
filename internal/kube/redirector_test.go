package kube

import "testing"

func TestNewRedirectorValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		config RedirectConfig
		valid  bool
	}{
		{name: "valid", config: RedirectConfig{AppPort: 8080, AgentPort: 15080, ProxyPort: 15081}, valid: true},
		{name: "invalid table", config: RedirectConfig{TableName: "bad table", AppPort: 8080, AgentPort: 15080, ProxyPort: 15081}},
		{name: "zero port", config: RedirectConfig{AppPort: 0, AgentPort: 15080, ProxyPort: 15081}},
		{name: "duplicate port", config: RedirectConfig{AppPort: 8080, AgentPort: 8080, ProxyPort: 15081}},
		{name: "invalid pod ip", config: RedirectConfig{AppPort: 8080, AgentPort: 15080, ProxyPort: 15081, PodIP: "not-an-ip"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewRedirector(test.config)
			if test.valid && err != nil {
				t.Fatalf("NewRedirector: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("NewRedirector succeeded, want error")
			}
		})
	}
}
