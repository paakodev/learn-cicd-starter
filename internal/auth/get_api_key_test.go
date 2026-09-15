package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		authorize  string
		wantKey    string
		wantErr    error
		wantErrMsg string
	}{
		{
			name:    "missing authorization header",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:       "malformed authorization header",
			authorize:  "Bearer token",
			wantErrMsg: "malformed authorization header",
		},
		{
			name:       "missing api key",
			authorize:  "ApiKey",
			wantErrMsg: "malformed authorization header",
		},
		{
			name:      "valid authorization header",
			authorize: "ApiKey test-api-key",
			wantKey:   "test-api-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.authorize != "" {
				headers.Set("Authorization", tt.authorize)
			}

			gotKey, gotErr := GetAPIKey(headers)
			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() key = %q, want %q", gotKey, tt.wantKey)
			}
			if tt.wantErr != nil && !errors.Is(gotErr, tt.wantErr) {
				t.Errorf("GetAPIKey() error = %v, want %v", gotErr, tt.wantErr)
			}
			if tt.wantErrMsg != "" && (gotErr == nil || gotErr.Error() != tt.wantErrMsg) {
				t.Errorf("GetAPIKey() error = %v, want %q", gotErr, tt.wantErrMsg)
			}
		})
	}
}
