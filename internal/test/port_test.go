package test

import "testing"

func TestNextPortCandidateWraps(t *testing.T) {
	portRange := maxNodePort - defaultNodePort + 1

	testCases := []struct {
		name     string
		lastPort int
		attempt  int
		want     int
	}{{
		name:     "first after default",
		lastPort: defaultNodePort,
		attempt:  1,
		want:     defaultNodePort + 1,
	}, {
		name:     "try max port",
		lastPort: maxNodePort - 1,
		attempt:  1,
		want:     maxNodePort,
	}, {
		name:     "wrap after max port",
		lastPort: maxNodePort,
		attempt:  1,
		want:     defaultNodePort,
	}, {
		name:     "wrap after trying max port",
		lastPort: maxNodePort - 1,
		attempt:  2,
		want:     defaultNodePort,
	}, {
		name:     "full scan ends on starting port",
		lastPort: maxNodePort - 1,
		attempt:  portRange,
		want:     maxNodePort - 1,
	}}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			got := nextPortCandidate(tc.lastPort, tc.attempt)
			if got != tc.want {
				t.Fatalf("want %d, got %d", tc.want, got)
			}
		})
	}
}
