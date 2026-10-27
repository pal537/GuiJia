package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	_ "image/png"
	"strings"
	"testing"
)

func decodeQRDataURI(t *testing.T, uri string) image.Config {
	t.Helper()
	const prefix = "data:image/png;base64,"
	if !strings.HasPrefix(uri, prefix) {
		t.Fatalf("二维码应为 PNG data URI, 得到前缀 %q", uri[:min(len(uri), 40)])
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(uri, prefix))
	if err != nil {
		t.Fatalf("data URI base64 解码失败: %v", err)
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("PNG 配置解码失败: %v", err)
	}
	if _, _, err := image.Decode(bytes.NewReader(raw)); err != nil {
		t.Fatalf("PNG 完整解码失败: %v", err)
	}
	return cfg
}

func TestTOTPQRCodePNG(t *testing.T) {
	uri, err := totpQRCodePNG("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	cfg := decodeQRDataURI(t, uri)
	if cfg.Width != 256 || cfg.Height != 256 {
		t.Errorf("二维码应为 256x256, 得到 %dx%d", cfg.Width, cfg.Height)
	}
}

func TestTOTPSetupReturnsQR(t *testing.T) {
	authTestSetup(t)
	rec := doJSON(t, handleAuthTOTPSetup, "POST", "/api/auth/totp/setup", `{}`, "203.0.113.9:1234")
	if rec.Code != 200 {
		t.Fatalf("获取密钥应 200, 得到 %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Secret string `json:"secret"`
		URL    string `json:"otpauth_url"`
		QR     string `json:"qr"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Secret == "" || resp.QR == "" {
		t.Fatalf("密钥与二维码都不应为空: %+v", resp)
	}
	if !strings.Contains(resp.URL, resp.Secret) {
		t.Fatalf("otpauth URL 应含密钥: %s", resp.URL)
	}
	cfg := decodeQRDataURI(t, resp.QR)
	if cfg.Width != 256 || cfg.Height != 256 {
		t.Errorf("接口返回的二维码应为 256x256, 得到 %dx%d", cfg.Width, cfg.Height)
	}
}
