package proton

import (
	"github.com/google/uuid"
)

const (
	SpoofedAppVersion       = "5.18.75.1"
	SpoofedModel            = "Pixel 9"
	SpoofedManufacturer     = "Google"
	SpoofedAndroidVersion   = "14"
	SpoofedUserAgent        = "PVPN/5.18.75.1 (Android 14; Google Pixel 9)"
	SpoofedAppVersionHeader = "android-vpn@5.18.75.1-dev+play"
	ProtonAPIBaseURL        = "https://vpn-api.proton.me"
)

// JavaStringHashCode calculates a 32-bit Java String.hashCode() value, matching Kotlin/Android runtime.
func JavaStringHashCode(s string) int32 {
	var h int32
	for i := 0; i < len(s); i++ {
		h = h*31 + int32(s[i])
	}
	return h
}

// GetDeviceHash generates a realistic, random device hash based on UUID to prevent device fingerprint pooling.
func GetDeviceHash() int32 {
	u := uuid.New().String()
	return JavaStringHashCode(u)
}

// BuildChallengePayload builds the vpn-android-v4-challenge-0 challenge JSON payload required by Proton API.
func BuildChallengePayload(deviceHash int32) map[string]any {
	return map[string]any{
		"Payload": map[string]any{
			"vpn-android-v4-challenge-0": map[string]any{
				"type":                 "me.proton.core.challenge.data.frame.ChallengeFrame.Device",
				"v":                    SpoofedAppVersion,
				"appLang":              "en",
				"timezone":             "America/New_York",
				"deviceName":           deviceHash,
				"regionCode":           "US",
				"timezoneOffset":       240,
				"isJailbreak":          false,
				"preferredContentSize": "1.0",
				"storageCapacity":      128.0,
				"isDarkmodeOn":         false,
				"keyboards":            []string{"com.google.android.inputmethod.latin"},
			},
		},
	}
}
