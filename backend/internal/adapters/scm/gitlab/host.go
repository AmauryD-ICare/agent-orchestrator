package gitlab

import "strings"

// NormalizeHost lowercases and trims a host string. This is the canonical
// normalization used by both the SCM provider and the tracker for host
// comparison and allowlist lookup.
func NormalizeHost(host string) string {
	return strings.ToLower(strings.TrimSpace(host))
}

// IsGitLabDotCom reports whether host refers to the default GitLab instance
// (gitlab.com). The empty string, "gitlab.com", and "www.gitlab.com" all
// map to the default instance and use the default base URL + token.
func IsGitLabDotCom(host string) bool {
	host = NormalizeHost(host)
	return host == "" || host == "gitlab.com" || host == "www.gitlab.com"
}

// RESTBaseForHost returns the REST API v4 base URL for a self-managed host.
// override is an optional web base URL ("https://host:8443/gitlab") from
// configuration; without one the base is https://<host>/api/v4. host is the
// web authority (SSH transport ports never belong here).
func RESTBaseForHost(host, override string) string {
	if override = strings.TrimRight(strings.TrimSpace(override), "/"); override != "" {
		return override + "/api/v4"
	}
	return "https://" + NormalizeHost(host) + "/api/v4"
}

// NormalizeHostBaseURLs re-keys a host->web base URL map by NormalizeHost.
func NormalizeHostBaseURLs(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for h, base := range in {
		if h = NormalizeHost(h); h != "" && strings.TrimSpace(base) != "" {
			out[h] = base
		}
	}
	return out
}
