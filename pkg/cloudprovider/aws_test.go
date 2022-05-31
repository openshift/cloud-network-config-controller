package cloudprovider

import (
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
