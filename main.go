package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
)

var keyringGet = func(service, user string) (string, error) {
	return keyring.Get(service, user)
}

type tokenResult struct {
	token string
	err   error
}

func lookupKeyring(ctx context.Context, service, user string) (string, error) {
	ch := make(chan tokenResult, 1)
	go func() {
		token, err := keyringGet(service, user)
		ch <- tokenResult{token, err}
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case res := <-ch:
		return res.token, res.err
	}
}

func isDebugEnabled() bool {
	debug := os.Getenv("GH_DEBUG")
	return debug == "1" || debug == "true" || strings.Contains(debug, "api")
}

func resolveToken() (string, error) {
	if token := os.Getenv("GH_TOKEN"); token != "" {
		if isDebugEnabled() {
			fmt.Fprintln(os.Stderr, "DEBUG: using token from GH_TOKEN")
		}
		return token, nil
	}

	timeout := 5 * time.Second
	if val := os.Getenv("GH_KEYRING_TIMEOUT"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			timeout = d
		} else if secs, err := strconv.Atoi(val); err == nil {
			timeout = time.Duration(secs) * time.Second
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	token, err := lookupKeyring(ctx, "github.com", "user")
	duration := time.Since(start)

	if isDebugEnabled() {
		if err != nil {
			fmt.Fprintf(os.Stderr, "DEBUG: keyring lookup failed after %v: %v\n", duration, err)
		} else {
			fmt.Fprintf(os.Stderr, "DEBUG: keyring lookup succeeded after %v\n", duration)
		}
	}

	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || (ctx.Err() != nil) {
			return "", fmt.Errorf("keyring lookup timed out")
		}

		if errors.Is(err, keyring.ErrNotFound) || strings.Contains(err.Error(), "not found") {
			if mockToken := os.Getenv("MOCK_HOSTS_TOKEN"); mockToken != "" {
				if isDebugEnabled() {
					fmt.Fprintln(os.Stderr, "DEBUG: using token from hosts.yml")
				}
				return mockToken, nil
			}
			return "", nil
		}

		return "", fmt.Errorf("keyring lookup failed: %w", err)
	}

	return token, nil
}

func main() {
	cmdRequiresAuth := false
	for _, arg := range os.Args[1:] {
		if arg == "api" || arg == "graphql" {
			cmdRequiresAuth = true
			break
		}
	}

	token, err := resolveToken()
	if err != nil {
		if strings.Contains(err.Error(), "timed out") {
			fmt.Fprintln(os.Stderr, "Error: Keyring lookup timed out. Please ensure your keyring daemon is running or set the GH_TOKEN environment variable.")
		} else {
			fmt.Fprintf(os.Stderr, "Error: Keyring lookup failed: %v. Please ensure your keyring daemon is running or set the GH_TOKEN environment variable.\n", err)
		}
		if cmdRequiresAuth {
			os.Exit(1)
		}
	}

	if cmdRequiresAuth && token == "" {
		fmt.Fprintln(os.Stderr, "Error: No authentication token found. Please run 'gh auth login' or set the GH_TOKEN environment variable.")
		os.Exit(1)
	}

	if token != "" {
		fmt.Printf("Authenticated successfully with token: %s\n", token)
		} else {
		fmt.Println("Running as unauthenticated user.")
	}
}
