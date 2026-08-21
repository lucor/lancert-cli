package target

import "testing"

func TestParse(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"10.0.0.1", "172.16.0.1", "172.31.255.254", "192.168.1.50"} {
		if _, err := Parse(value); err != nil {
			t.Errorf("Parse(%q): %v", value, err)
		}
	}
	for _, value := range []string{"8.8.8.8", "100.64.0.1", "127.0.0.1", "169.254.1.1", "::1", "192.168.001.1", "bad"} {
		if _, err := Parse(value); err == nil {
			t.Errorf("Parse(%q) unexpectedly succeeded", value)
		}
	}
}
