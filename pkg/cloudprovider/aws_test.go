package cloudprovider

import (
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
)

func TestGetInstanceIdFromProviderId(t *testing.T) {
	tcs := []struct {
		input     string
		output    string
		errString string
	}{
		{
			input:  "aws:///us-west-2a/i-008447f243eead273",
			output: "i-008447f243eead273",
		},
		{
			input:  "aws://us-west-2a/i-008447f243eead273",
			output: "i-008447f243eead273",
		},
		{
			input:  "aws:////i-008447f243eead273",
			output: "i-008447f243eead273",
		},
		{
			input:  "aws:///i-008447f243eead273",
			output: "i-008447f243eead273",
		},
		{
			input:  "aws://i-008447f243eead273",
			output: "i-008447f243eead273",
		},
		{
			input:     "aws://",
			errString: "the URI is not expected: aws://",
		},
		{
			input:     "aws:///",
			errString: "the URI is not expected: aws:///",
		},
		{
			input:     "aws://///i-008447f243eead273",
			output:    "",
			errString: "the URI is not expected: aws://///i-008447f243eead273",
		},
	}

	var out string
	var err error
	for _, tc := range tcs {
		out, err = getInstanceIdFromProviderId(tc.input)
		if tc.errString != "" {
			if err != nil {
				if err.Error() != tc.errString {
					t.Fatalf("Expected error with error message %s but got %q",
						tc.errString, err)
				}
			} else {
				t.Fatalf("Expected an error, but got nil instead and output %s", out)
			}
		} else {
			if err != nil {
				t.Fatalf("Expected no error, but got an error instead: %q", err)

			} else {
				if out != tc.output {
					t.Fatalf("Expected output %s but got output %s instead", tc.output, out)
				}
			}
		}
	}
}

func TestSharedCredentialsFileFromDirectory(t *testing.T) {
	tcs := []struct {
		files     map[string]string
		fExpected string
		expected  string
		err       string
	}{
		{
			files: map[string]string{
				"credentials":           "content-of-credentials",
				"aws_access_key_id":     "content-of-access-key-id",
				"aws_secret_access_key": "content-of-secret-access-key",
			},
			expected: "content-of-credentials",
		},
		{
			files: map[string]string{
				"credentials": "content-of-credentials",
			},
			expected: "content-of-credentials",
		},
		{
			files: map[string]string{
				"aws_access_key_id":     "content-of-access-key-id",
				"aws_secret_access_key": "content-of-secret-access-key",
			},
			expected: fmt.Sprintf("[default]\naws_access_key_id = %s\naws_secret_access_key = %s\n",
				"content-of-access-key-id", "content-of-secret-access-key"),
		},
		{
			files: map[string]string{
				"aws_secret_access_key": "content-of-secret-access-key",
			},
			err: "aws_access_key_id: no such file or directory",
		},
	}

	for i, tc := range tcs {
		tmpdir := t.TempDir()
		for fileName, fileContent := range tc.files {
			err := os.WriteFile(path.Join(tmpdir, fileName), []byte(fileContent), 0644)
			if err != nil {
				t.Fatalf("TestSharedCredentialsFileFromDirectory (%d): Unexpected error creating file %s, err: %q",
					i, fileName, err)
			}
		}
		fExpected, err := sharedCredentialsFileFromDirectory(tmpdir)
		// Handle error testing.
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("TestSharedCredentialsFileFromDirectory (%d): Expected to get error with substring %q but got %q instead",
					i, tc.err, err)
			}
			continue
		}
		// Handle when no error should occur.
		if err != nil {
			t.Fatalf("TestSharedCredentialsFileFromDirectory (%d): Unexpected error from sharedCredentialsFileFromDirectory, err: %q",
				i, err)
		}
		expected, err := os.ReadFile(fExpected)
		if err != nil {
			t.Fatalf("TestSharedCredentialsFileFromDirectory (%d): Unexpected error reading expected file %s, err: %q",
				i, fExpected, err)
		}
		if string(expected) != tc.expected {
			t.Fatalf("TestSharedCredentialsFileFromDirectory (%d): Unexpected content, want %q but have %q",
				i, tc.expected, string(expected))
		}
	}
}
