package files

import (
	"crypto/rand"
	"fmt"
	"strings"
)

// passwordAlphabet is deliberately alphanumeric: the password rides the cifs options string,
// which is comma-separated with no escaping, and a Windows local password, so it must avoid
// the cifs separator and the shell/quote characters. Alphanumeric sidesteps all of them.
const passwordAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// passwordLength is long enough that the restricted alphabet still leaves ample entropy
// (62^32 ~= 190 bits).
const passwordLength = 32

// newPassword returns a fresh random password from passwordAlphabet.
func newPassword() (string, error) {
	b := make([]byte, passwordLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	out := make([]byte, passwordLength)
	for i, v := range b {
		out[i] = passwordAlphabet[int(v)%len(passwordAlphabet)]
	}
	return string(out), nil
}

// validPassword rejects a password that would break the cifs options string or a Windows
// command context: a comma (the cifs separator), a quote or backslash, a semicolon, or any
// whitespace. Empty is invalid too.
func validPassword(s string) error {
	if s == "" {
		return fmt.Errorf("password is empty")
	}
	if strings.ContainsAny(s, `,"\;`) || strings.ContainsAny(s, " \t\r\n") {
		return fmt.Errorf("password contains a forbidden character (comma, quote, backslash, semicolon, or whitespace)")
	}
	return nil
}
