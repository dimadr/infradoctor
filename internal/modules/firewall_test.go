package modules

import (
	"testing"
)

func TestExtractPolicy(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			name:   "input drop",
			output: "Chain INPUT (policy DROP)\ntarget     prot opt source",
			want:   "DROP",
		},
		{
			name:   "input accept",
			output: "Chain INPUT (policy ACCEPT)\ntarget     prot opt source",
			want:   "ACCEPT",
		},
		{
			name:   "forward drop",
			output: "Chain FORWARD (policy DROP)\ntarget     prot opt source",
			want:   "DROP",
		},
		{
			name:   "no policy",
			output: "Chain INPUT\ntarget     prot opt source",
			want:   "",
		},
		{
			name:   "empty",
			output: "",
			want:   "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractPolicy(tc.output)
			if got != tc.want {
				t.Errorf("extractPolicy(%q) = %q, want %q", tc.output, got, tc.want)
			}
		})
	}
}

func TestCountRules(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   int
	}{
		{
			name: "no rules",
			output: "Chain INPUT (policy ACCEPT)\n" +
				"num  target     prot opt source",
			want: 0,
		},
		{
			name: "three rules",
			output: "Chain INPUT (policy DROP)\n" +
				"num  target     prot opt source\n" +
				"1    ACCEPT     all  --  10.0.0.0/8\n" +
				"2    DROP       all  --  0.0.0.0/0\n" +
				"3    ACCEPT     tcp  --  1.2.3.4",
			want: 3,
		},
		{
			name:   "empty output",
			output: "",
			want:   0,
		},
		{
			name:   "only headers",
			output: "Chain FORWARD (policy DROP)",
			want:   0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := countRules(tc.output)
			if got != tc.want {
				t.Errorf("countRules(%q) = %d, want %d", tc.output, got, tc.want)
			}
		})
	}
}
