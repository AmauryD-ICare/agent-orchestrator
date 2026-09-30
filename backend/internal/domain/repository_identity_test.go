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
		{"ssh port is not web authority", "ssh://git@gitlab.example.com:2200/alice/repo.git", "https://gitlab.example.com/group/repo", true},
		{"ssh port cannot be a web port", "ssh://git@gitlab.example.com:2200/alice/repo.git", "https://gitlab.example.com:2200/group/repo", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ProjectConfig{CanonicalRepoURL: tc.canonical}
			if err := cfg.ValidateCanonicalRepository(tc.origin); (err == nil) != tc.valid {
				t.Fatalf("validation = %v, valid=%v", err, tc.valid)
			}
		})
	}
}

func TestParseRepositoryIdentitySSHPortIsTransportOnly(t *testing.T) {
	for _, tc := range []struct{ raw, wantHost string }{
		{"ssh://git@gitlab.icareweb.com:2200/group/repo.git", "gitlab.icareweb.com"},
		{"ssh://git@GitLab.icareweb.com/group/repo.git", "gitlab.icareweb.com"},
		{"git@gitlab.icareweb.com:group/repo.git", "gitlab.icareweb.com"},
		{"https://gitlab.icareweb.com/group/repo.git", "gitlab.icareweb.com"},
		{"https://gitlab.icareweb.com:8443/group/repo.git", "gitlab.icareweb.com:8443"},
	} {
		id, err := ParseRepositoryIdentity(tc.raw)
		if err != nil {
			t.Fatalf("ParseRepositoryIdentity(%q): %v", tc.raw, err)
		}
		if id.Host != tc.wantHost || id.Provider != "gitlab" || id.Namespace != "group" || id.Name != "repo" {
			t.Errorf("ParseRepositoryIdentity(%q) = %+v, want host %q", tc.raw, id, tc.wantHost)
		}
	}
}
