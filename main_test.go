package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

func TestLookupKeyring_Success(t *testing.T) {
	keyringGet = func(service, user string) (string, error) {
		return "my-secret-token", nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	token, err := lookupKeyring(ctx, "service", "user")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if token != "my-secret-token" {
		t.Errorf("expected my-secret-token, got %s", token)
	}
}

func TestLookupKeyring_Timeout(t *testing.T) {
	keyringGet = func(service, user string) (string, error) {
		time.Sleep(2 * time.Second)
		return "token", nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := lookupKeyring(ctx, "service", "user")
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}
}

func TestLookupKeyring_NotFound(t *testing.T) {
	keyringGet = func(service, user string) (string, error) {
		return "", keyring.ErrNotFound
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := lookupKeyring(ctx, "service", "user")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, keyring.ErrNotFound) {
		t.Errorf("expected keyring.ErrNotFound, got %v", err)
	}
}

func TestResolveToken_Timeout(t *testing.T) {
	keyringGet = func(service, user string) (string, error) {
		time.Sleep(2 * time.Second)
		return "token", nil
	}

	os.Setenv("GH_KEYRING_TIMEOUT", "100ms")
	defer os.Unsetenv("GH_KEYRING_TIMEOUT")

	_, err := resolveToken()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("expected timeout error, got %v", err)
	}
}

func TestResolveToken_SystemError(t *testing.T) {
	keyringGet = func(service, user string) (string, error) {
		return "", errors.New("dbus connection failed")
	}

	_, err := resolveToken()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "dbus connection failed") {
		t.Errorf("expected dbus error, got %v", err)
	}
}

func TestResolveToken_NotFoundFallback(t *testing.T) {
	keyringGet = func(service, user string) (string, error) {
		return "", keyring.ErrNotFound
	}

	os.Setenv("MOCK_HOSTS_TOKEN", "hosts-token")
	defer os.Unsetenv("MOCK_HOSTS_TOKEN")

	token, err := resolveToken()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if token != "hosts-token" {
		t.Errorf("expected hosts-token, got %s", token)
	}
}
