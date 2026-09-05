package main

import "testing"

const (
	digest1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digest2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	digest3 = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

func TestIncompleteArchiveErr(t *testing.T) {
	t.Parallel()

	missingBlob := "image scan failed: scan error: failed to initialize the struct from the temporary file: file blobs/sha256/9e94bb97a736959a44b9bffeeecea3fffcb41d0ccdb940778615580cba7eede0 not found in tar"
	missingTag := "unable to open: tag git.yak-wall.ts.net/containers-mirror/adze:dev not found in tarball"

	if !incompleteArchiveErr(errString(missingBlob)) {
		t.Error("incompleteArchiveErr should match a missing blob error")
	}
	if incompleteArchiveErr(nil) {
		t.Error("incompleteArchiveErr should not match nil")
	}
	if incompleteArchiveErr(errString("no such image")) {
		t.Error("incompleteArchiveErr should not match unrelated errors")
	}
	if incompleteArchiveErr(errString(missingTag)) {
		t.Error("incompleteArchiveErr should not match the 'tag not found in tarball' error")
	}
}

func TestDigestFor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ref     string
		digests []string
		want    string
		wantOK  bool
	}{
		{
			name:    "matches same repository",
			ref:     "git.yak-wall.ts.net/containers-mirror/adze:dev",
			digests: []string{"other.example.com/foo@" + digest1, "git.yak-wall.ts.net/containers-mirror/adze@" + digest2},
			want:    "git.yak-wall.ts.net/containers-mirror/adze@" + digest2,
			wantOK:  true,
		},
		{
			name:    "no digest for this repository",
			ref:     "git.yak-wall.ts.net/containers-mirror/adze:dev",
			digests: []string{"other.example.com/foo@" + digest1},
			wantOK:  false,
		},
		{
			name:    "matches short names after normalisation",
			ref:     "adze:dev",
			digests: []string{"adze", "docker.io/library/adze@" + digest3},
			want:    "docker.io/library/adze@" + digest3,
			wantOK:  true,
		},
		{
			name:    "unparseable reference",
			ref:     "git.yak-wall.ts.net/containers-mirror/adze:dev:extra",
			digests: []string{"git.yak-wall.ts.net/containers-mirror/adze@" + digest2},
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := digestFor(tt.ref, tt.digests)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("digestFor(%q, %v) = (%q, %v), want (%q, %v)", tt.ref, tt.digests, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

type errString string

func (e errString) Error() string { return string(e) }
