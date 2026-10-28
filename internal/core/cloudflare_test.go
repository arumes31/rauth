package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func cloudflareListServer(t *testing.T, v4, v6 string, status int) []string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if strings.HasSuffix(r.URL.Path, "v6") {
			_, _ = w.Write([]byte(v6))
			return
		}
		_, _ = w.Write([]byte(v4))
	}))
	t.Cleanup(srv.Close)
	return []string{srv.URL + "/ips-v4", srv.URL + "/ips-v6"}
}

func TestFetchCloudflareRanges(t *testing.T) {
	v4 := strings.Join(DefaultCloudflareIPRanges[:15], "\n") + "\n"
	v6 := strings.Join(DefaultCloudflareIPRanges[15:], "\n")

	t.Run("valid lists", func(t *testing.T) {
		urls := cloudflareListServer(t, v4, v6, http.StatusOK)
		got, err := fetchCloudflareRanges(context.Background(), http.DefaultClient, urls)
		require.NoError(t, err)
		assert.ElementsMatch(t, DefaultCloudflareIPRanges, got)
	})

	t.Run("invalid entry rejects the whole refresh", func(t *testing.T) {
		urls := cloudflareListServer(t, v4+"not-a-cidr\n", v6, http.StatusOK)
		_, err := fetchCloudflareRanges(context.Background(), http.DefaultClient, urls)
		assert.Error(t, err)
	})

	t.Run("truncated list is rejected", func(t *testing.T) {
		urls := cloudflareListServer(t, "173.245.48.0/20\n", "", http.StatusOK)
		_, err := fetchCloudflareRanges(context.Background(), http.DefaultClient, urls)
		assert.Error(t, err)
	})

	t.Run("HTTP error is rejected", func(t *testing.T) {
		urls := cloudflareListServer(t, v4, v6, http.StatusInternalServerError)
		_, err := fetchCloudflareRanges(context.Background(), http.DefaultClient, urls)
		assert.Error(t, err)
	})
}

func TestCloudflareRangesUpdate(t *testing.T) {
	t.Cleanup(func() { SetCloudflareRanges(DefaultCloudflareIPRanges) })

	assert.True(t, IsCloudflareIP("104.16.0.1"))
	assert.False(t, IsCloudflareIP("198.51.100.1"))

	SetCloudflareRanges([]string{"198.51.100.0/24", "bogus"})
	assert.True(t, IsCloudflareIP("198.51.100.1"))
	assert.False(t, IsCloudflareIP("104.16.0.1"))

	// An empty or fully invalid update keeps the current list.
	SetCloudflareRanges([]string{"bogus"})
	assert.True(t, IsCloudflareIP("198.51.100.1"))
}
