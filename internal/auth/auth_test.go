package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("Valid Authorization Header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey my-secret-key")

		apiKey, err := GetAPIKey(headers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if apiKey != "my-secret-key" {
			t.Errorf("expected API key to be 'my-secret-key', got '%s'", apiKey)
		}
	})

	t.Run("Missing Authorization Header", func(t *testing.T) {
		headers := http.Header{}

		apiKey, err := GetAPIKey(headers)
		if err == nil || err != ErrNoAuthHeaderIncluded {
			t.Fatalf("expected error '%v', got '%v'", ErrNoAuthHeaderIncluded, err)
		}

		if apiKey != "" {
			t.Errorf("expected API key to be empty, got '%s'", apiKey)
		}
	})

	t.Run("Malformed Authorization Header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer my-secret-key") // Wrong scheme

		apiKey, err := GetAPIKey(headers)
		expectedErr := "malformed authorization header"
		if err == nil || err.Error() != expectedErr {
			t.Fatalf("expected error '%s', got '%v'", expectedErr, err)
		}

		if apiKey != "" {
			t.Errorf("expected API key to be empty, got '%s'", apiKey)
		}
	})
}
