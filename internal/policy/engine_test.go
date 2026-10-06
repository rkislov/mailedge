package policy_test

import (
	"context"
	"testing"

	"github.com/rkislov/mailedge/internal/config"
	"github.com/rkislov/mailedge/internal/mailmsg"
	"github.com/rkislov/mailedge/internal/policy"
)

func TestEngineRulesPriority(t *testing.T) {
	en := true
	cfg := &config.Config{
		Policy: config.PolicyConfig{
			DefaultAction: "accept",
			Rules: []config.PolicyRule{
				{ID: "later", Priority: 50, Action: "quarantine", Enabled: &en, Match: config.PolicyMatch{From: "*@evil.example"}},
				{ID: "first", Priority: 10, Action: "reject", Enabled: &en, Match: config.PolicyMatch{From: "*@evil.example"}},
			},
		},
	}
	eng := policy.New(cfg)
	res, err := eng.Evaluate(context.Background(), &mailmsg.Message{From: "a@evil.example"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != "reject" || res.Details["rule"] != "first" {
		t.Fatalf("got %+v", res)
	}
}

func TestEngineCIDRAndSubject(t *testing.T) {
	en := true
	cfg := &config.Config{
		Policy: config.PolicyConfig{
			DefaultAction: "accept",
			Rules: []config.PolicyRule{
				{
					ID: "cidr", Priority: 1, Action: "discard", Enabled: &en,
					Match: config.PolicyMatch{RemoteIP: "10.0.0.0/8", SubjectRe: "(?i)spam"},
				},
			},
		},
	}
	eng := policy.New(cfg)
	res, err := eng.Evaluate(context.Background(), &mailmsg.Message{
		From: "a@x", RemoteIP: "10.1.2.3", Subject: "Buy SPAM now",
	}, []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != "discard" {
		t.Fatalf("want discard got %s", res.Action)
	}
}
