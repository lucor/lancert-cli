package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"go.lucor.dev/lancert-cli/internal/app"
)

func TestVersionCommandDoesNotInitializeState(t *testing.T) {
	var output bytes.Buffer
	command := newCommand("/path/that/is/not/used", strings.NewReader(""), &output, &output)
	if err := command.Run(context.Background(), []string{app.ProductName, "version"}); err != nil {
		t.Fatal(err)
	}
	if output.String() != Version+"\n" {
		t.Fatalf("version output = %q", output.String())
	}
}

func TestTermsPrompt(t *testing.T) {
	var output bytes.Buffer
	accepted, err := confirmTerms(strings.NewReader("yes\n"), &output)
	if err != nil || !accepted {
		t.Fatalf("confirmTerms(yes) = %v, %v", accepted, err)
	}
	accepted, err = confirmTerms(strings.NewReader("no\n"), &output)
	if err == nil || accepted {
		t.Fatalf("confirmTerms(no) = %v, %v", accepted, err)
	}
}
