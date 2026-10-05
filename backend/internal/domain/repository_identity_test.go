package domain

import "testing"

func TestCanonicalRepositoryValidation(t *testing.T) {
	for _, tc := range []struct {
		name, origin, canonical string
		valid                   bool
	}{
		{"legacy", "", "", true},
		{"authenticated checkout origin", "https://git-user:token@github.com/alice/repo.git", "https://github.com/acme/repo", true},
		{"github fork", "git@github.com:alice/repo.git", "https://github.com/acme/repo", true},
		{"gitlab nested", "ssh://git@gitlab.example.com/alice/team/repo.git", "https://gitlab.example.com/group/subgroup/repo", true},
		{"cross host", "https://gitlab.com/alice/repo", "https://gitlab.example.com/group/repo", false},
		{"cross provider", "https://github.com/alice/repo", "https://gitlab.com/group/repo", false},
		{"no origin", "", "https://github.com/acme/repo", false},
		{"remote name", "https://github.com/alice/repo", "upstream", false},
		{"PR URL", "https://github.com/alice/repo", "https://github.com/acme/repo/pull/7", false},
		{"MR URL", "https://gitlab.com/alice/repo", "https://gitlab.com/acme/repo/-/merge_requests/7", false},
		{"query", "https://github.com/alice/repo", "https://github.com/acme/repo?x=y", false},
		{"credentials", "https://github.com/alice/repo", "https://user:secret@github.com/acme/repo", false},
		{"traversal", "https://gitlab.com/alice/repo", "https://gitlab.com/acme/../repo", false},
		{"encoded namespace", "https://gitlab.com/alice/repo", "https://gitlab.com/acme%2fsub/repo", false},
		{"custom authority", "https://gitlab.example.com:8443/alice/repo", "https://gitlab.example.com:8443/group/sub/repo", true},
		{"port", "https://github.com/alice/repo", "https://github.com:8443/acme/repo", false},
		{"ssh origin port ignored", "ssh://git@gitlab.icareweb.com:2200/production_software/new-pogo-multi-gateway.git", "https://gitlab.icareweb.com/production_software/new-pogo-multi-gateway", true},
		{"ssh origin port is not an HTTPS authority", "ssh://git@gitlab.icareweb.com:2200/production_software/new-pogo-multi-gateway.git", "https://gitlab.icareweb.com:2200/production_software/new-pogo-multi-gateway", false},
		{"ssh origin different host", "ssh://git@gitlab.other.com:2200/production_software/new-pogo-multi-gateway.git", "https://gitlab.icareweb.com/production_software/new-pogo-multi-gateway", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ProjectConfig{CanonicalRepoURL: tc.canonical}
			if err := cfg.ValidateCanonicalRepository(tc.origin); (err == nil) != tc.valid {
				t.Fatalf("validation = %v, valid=%v", err, tc.valid)
			}
		})
	}
}

func TestRepositoryIdentityComparesSSHByHostAndPath(t *testing.T) {
	want := RepositoryIdentity{Provider: "gitlab", Host: "gitlab.icareweb.com", Namespace: "production_software", Name: "new-pogo-multi-gateway"}
	for _, tc := range []struct {
		name, raw string
		same      bool
	}{
		{"ssh URL with port", "ssh://git@gitlab.icareweb.com:2200/production_software/new-pogo-multi-gateway.git", true},
		{"https repository URL", "https://gitlab.icareweb.com/production_software/new-pogo-multi-gateway", true},
		{"scp-style", "git@gitlab.icareweb.com:production_software/new-pogo-multi-gateway.git", true},
		{"different host", "ssh://git@gitlab.other.com:2200/production_software/new-pogo-multi-gateway.git", false},
		{"https port kept", "https://gitlab.icareweb.com:2200/production_software/new-pogo-multi-gateway", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRepositoryIdentity(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			if (got == want) != tc.same {
				t.Fatalf("identity = %+v, want same=%v as %+v", got, tc.same, want)
			}
		})
	}
}
