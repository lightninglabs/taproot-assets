package rpcserver

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeBase64AnyVariant(t *testing.T) {
	t.Parallel()

	testBytes := []byte{
		0x03, 0x1f, 0x55, 0x8d, 0xa2, 0x07, 0xc9, 0x31,
		0x44, 0xaa, 0x70, 0xbe, 0x96, 0x11, 0x22, 0x6f,
		0x87, 0x0c, 0xff, 0x13, 0x4a, 0x90, 0xde, 0x33,
		0x56, 0x71, 0x44, 0x88, 0x99, 0x20, 0x0a, 0x4f,
	}

	testCases := []struct {
		name  string
		value string
	}{
		{
			name:  "std",
			value: base64.StdEncoding.EncodeToString(testBytes),
		},
		{
			name:  "url",
			value: base64.URLEncoding.EncodeToString(testBytes),
		},
		{
			name:  "raw std",
			value: base64.RawStdEncoding.EncodeToString(testBytes),
		},
		{
			name:  "raw url",
			value: base64.RawURLEncoding.EncodeToString(testBytes),
		},
	}

	for _, testCase := range testCases {
		tc := testCase

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			decodedValue, err := decodeBase64AnyVariant(tc.value)
			require.NoError(t, err)
			require.Equal(t, testBytes, decodedValue)
		})
	}
}

func TestDecodeBase64AnyVariantInvalid(t *testing.T) {
	t.Parallel()

	_, err := decodeBase64AnyVariant("not base64")
	require.Error(t, err)
}

func TestNormalizeRESTBytesQueryValues(t *testing.T) {
	t.Parallel()

	groupKey := []byte{
		0x02, 0xf0, 0x16, 0x98, 0x6d, 0x4b, 0xc1, 0x42,
		0xac, 0x19, 0x77, 0x36, 0x41, 0x22, 0xbb, 0x9a,
		0x3f, 0xee, 0x10, 0xd0, 0x98, 0x24, 0x07, 0xf8,
		0x43, 0x7a, 0x29, 0x6d, 0x51, 0x58, 0xcd, 0xab,
	}
	assetID := []byte{
		0x03, 0x77, 0x12, 0x5a, 0xc8, 0x11, 0x22, 0xef,
		0x07, 0x88, 0xca, 0x31, 0x49, 0x41, 0xdd, 0xa9,
		0x6b, 0xae, 0x80, 0x29, 0x34, 0x12, 0x80, 0x71,
		0x0f, 0x66, 0xb4, 0x7c, 0x2a, 0x52, 0x44, 0x95,
	}

	values := url.Values{
		"group_key": []string{
			base64.RawURLEncoding.EncodeToString(groupKey),
		},
		"batch_key": []string{
			base64.RawStdEncoding.EncodeToString(groupKey),
		},
		"asset_id": []string{
			base64.RawURLEncoding.EncodeToString(assetID),
		},
		"asset_filter": []string{
			base64.RawStdEncoding.EncodeToString(assetID),
		},
		"asset_specifier.group_key": []string{
			base64.StdEncoding.EncodeToString(groupKey),
		},
		"asset_specifier.asset_id": []string{
			base64.StdEncoding.EncodeToString(assetID),
		},
		"unrelated_key": []string{"not-base64"},
	}

	err := normalizeRESTBytesQueryValues(values)
	require.NoError(t, err)

	require.Equal(
		t, base64.URLEncoding.EncodeToString(groupKey),
		values.Get("group_key"),
	)
	require.Equal(
		t, base64.URLEncoding.EncodeToString(groupKey),
		values.Get("batch_key"),
	)
	require.Equal(
		t, base64.URLEncoding.EncodeToString(assetID),
		values.Get("asset_id"),
	)
	require.Equal(
		t, base64.URLEncoding.EncodeToString(assetID),
		values.Get("asset_filter"),
	)
	require.Equal(
		t, base64.URLEncoding.EncodeToString(groupKey),
		values.Get("asset_specifier.group_key"),
	)
	require.Equal(
		t, base64.URLEncoding.EncodeToString(assetID),
		values.Get("asset_specifier.asset_id"),
	)
	require.Equal(t, "not-base64", values.Get("unrelated_key"))
}

func TestNormalizeRESTBytesQueryValuesInvalid(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		values url.Values
	}{
		{
			name: "group key filter",
			values: url.Values{
				"group_key_filter": []string{"***"},
			},
		},
		{
			name: "asset id",
			values: url.Values{
				"asset_id": []string{"***"},
			},
		},
		{
			name: "batch key",
			values: url.Values{
				"batch_key": []string{"***"},
			},
		},
	}

	for _, testCase := range testCases {
		tc := testCase

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := normalizeRESTBytesQueryValues(tc.values)
			require.Error(t, err)
		})
	}
}

func TestNormalizeRESTBytesPath(t *testing.T) {
	t.Parallel()

	batchKey := []byte{
		0x03, 0x9f, 0x2a, 0x1b, 0x51, 0x44, 0x9a, 0xc8,
		0x1f, 0x70, 0x43, 0xcc, 0xa1, 0x33, 0x6b, 0x28,
		0x4a, 0xf2, 0x99, 0x77, 0x5c, 0x23, 0xe7, 0xac,
		0x14, 0x99, 0x7a, 0x0e, 0x42, 0x09, 0xfd, 0x90,
		0x6f,
	}

	req := httptest.NewRequest(
		http.MethodGet,
		mintBatchesPathPrefix+
			base64.RawURLEncoding.EncodeToString(batchKey),
		nil,
	)

	err := normalizeRESTBytesPath(req)
	require.NoError(t, err)

	require.Equal(
		t, mintBatchesPathPrefix+
			base64.URLEncoding.EncodeToString(batchKey),
		req.URL.Path,
	)
}

func TestNormalizeRESTBytesPathEscapedSlash(t *testing.T) {
	t.Parallel()

	batchKey := []byte{
		0xff, 0xfb, 0xfe, 0xef, 0x11, 0x09, 0xca, 0x72,
		0x98, 0x4a, 0xb4, 0x33, 0x7d, 0x62, 0x04, 0xc9,
		0x10, 0x82, 0x71, 0xaa, 0x39, 0x91, 0xcf, 0x61,
		0x12, 0x79, 0xe0, 0x3d, 0x4a, 0xc6, 0x00, 0x9f,
		0xee,
	}

	stdEncodedBatchKey := base64.StdEncoding.EncodeToString(batchKey)
	req := httptest.NewRequest(
		http.MethodGet,
		mintBatchesPathPrefix+url.PathEscape(stdEncodedBatchKey),
		nil,
	)

	err := normalizeRESTBytesPath(req)
	require.NoError(t, err)
	require.Equal(
		t, mintBatchesPathPrefix+
			base64.URLEncoding.EncodeToString(batchKey),
		req.URL.Path,
	)
}

func TestNormalizeRESTBytesPathUsesEscapedPath(t *testing.T) {
	t.Parallel()

	batchKey := []byte{
		0x03, 0x9f, 0x2a, 0x1b, 0x51, 0x44, 0x9a, 0xc8,
		0x1f, 0x70, 0x43, 0xcc, 0xa1, 0x33, 0x6b, 0x28,
		0x4a, 0xf2, 0x99, 0x77, 0x5c, 0x23, 0xe7, 0xac,
		0x14, 0x99, 0x7a, 0x0e, 0x42, 0x09, 0xfd, 0x90,
		0x6f,
	}

	rawURLBatchKey := base64.RawURLEncoding.EncodeToString(batchKey)
	req := httptest.NewRequest(
		http.MethodGet, mintBatchesPathPrefix+"placeholder", nil,
	)
	req.URL.Path = mintBatchesPathPrefix + rawURLBatchKey
	req.URL.RawPath = mintBatchesPathPrefix + rawURLBatchKey
	req.RequestURI = "https://example.com" + mintBatchesPathPrefix + "***"

	err := normalizeRESTBytesPath(req)
	require.NoError(t, err)
	require.Equal(
		t, mintBatchesPathPrefix+
			base64.URLEncoding.EncodeToString(batchKey),
		req.URL.Path,
	)
}

func TestNormalizeRESTBytesPathUniverseHexParams(t *testing.T) {
	t.Parallel()

	const (
		universeRootsAssetIDPathPrefix = "/v1/taproot-assets/" +
			"universe/roots/asset-id/"
		universeRootsGroupKeyPathPrefix = "/v1/taproot-assets/" +
			"universe/roots/group-key/"
		universeProofsAssetIDPathPrefix = "/v1/taproot-assets/" +
			"universe/proofs/asset-id/"
		universeProofsPushGroupKeyPathPrefix = "/v1/taproot-assets/" +
			"universe/proofs/push/group-key/"
	)

	assetID := []byte{
		0x03, 0x77, 0x12, 0x5a, 0xc8, 0x11, 0x22, 0xef,
		0x07, 0x88, 0xca, 0x31, 0x49, 0x41, 0xdd, 0xa9,
		0x6b, 0xae, 0x80, 0x29, 0x34, 0x12, 0x80, 0x71,
		0x0f, 0x66, 0xb4, 0x7c, 0x2a, 0x52, 0x44, 0x95,
	}
	groupKey := []byte{
		0x02, 0xf0, 0x16, 0x98, 0x6d, 0x4b, 0xc1, 0x42,
		0xac, 0x19, 0x77, 0x36, 0x41, 0x22, 0xbb, 0x9a,
		0x3f, 0xee, 0x10, 0xd0, 0x98, 0x24, 0x07, 0xf8,
		0x43, 0x7a, 0x29, 0x6d, 0x51, 0x58, 0xcd, 0xab,
	}

	testCases := []struct {
		name       string
		path       string
		wantPrefix string
		wantSuffix string
	}{
		{
			name: "roots asset id from base64",
			path: universeRootsAssetIDPathPrefix +
				base64.RawURLEncoding.EncodeToString(assetID),
			wantPrefix: universeRootsAssetIDPathPrefix,
			wantSuffix: hex.EncodeToString(assetID),
		},
		{
			name: "roots group key from base64",
			path: universeRootsGroupKeyPathPrefix +
				base64.RawURLEncoding.EncodeToString(groupKey),
			wantPrefix: universeRootsGroupKeyPathPrefix,
			wantSuffix: hex.EncodeToString(groupKey),
		},
		{
			name: "proofs asset id uppercase hex",
			path: universeProofsAssetIDPathPrefix +
				strings.ToUpper(hex.EncodeToString(assetID)) +
				"/" + hex.EncodeToString(assetID) + "/0/" +
				hex.EncodeToString(groupKey),
			wantPrefix: universeProofsAssetIDPathPrefix,
			wantSuffix: hex.EncodeToString(assetID) + "/" +
				hex.EncodeToString(assetID) + "/0/" +
				hex.EncodeToString(groupKey),
		},
		{
			name: "proofs push group key from base64",
			path: universeProofsPushGroupKeyPathPrefix +
				base64.RawURLEncoding.EncodeToString(groupKey) +
				"/" + hex.EncodeToString(assetID) + "/0/" +
				hex.EncodeToString(groupKey),
			wantPrefix: universeProofsPushGroupKeyPathPrefix,
			wantSuffix: hex.EncodeToString(groupKey) + "/" +
				hex.EncodeToString(assetID) + "/0/" +
				hex.EncodeToString(groupKey),
		},
	}

	for _, testCase := range testCases {
		tc := testCase

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			err := normalizeRESTBytesPath(req)
			require.NoError(t, err)
			expectedPath := tc.wantPrefix + tc.wantSuffix
			require.Equal(t, expectedPath, req.URL.Path)
		})
	}
}

func TestNormalizeRESTBytesPathInvalid(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(
		http.MethodGet, mintBatchesPathPrefix+"***", nil,
	)

	err := normalizeRESTBytesPath(req)
	require.Error(t, err)
}

func TestNormalizeRESTBytesPathInvalidUniverseParam(t *testing.T) {
	t.Parallel()

	testCases := []string{
		"/v1/taproot-assets/universe/roots/asset-id/***",
		"/v1/taproot-assets/universe/roots/group-key/***",
		"/v1/taproot-assets/universe/proofs/asset-id/***/00/0/00",
		"/v1/taproot-assets/universe/proofs/group-key/***/00/0/00",
	}

	for _, testCase := range testCases {
		path := testCase

		t.Run(path, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, path, nil)
			err := normalizeRESTBytesPath(req)
			require.Error(t, err)
		})
	}
}

func TestRESTBytesNormalizerMiddleware(t *testing.T) {
	t.Parallel()

	var nextCalled bool
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		nextCalled = true
	})

	middleware := NewRESTBytesNormalizer(next)
	req := httptest.NewRequest(
		http.MethodGet, mintBatchesPathPrefix+"***", nil,
	)
	resp := httptest.NewRecorder()

	middleware.ServeHTTP(resp, req)

	require.Equal(t, http.StatusBadRequest, resp.Code)
	require.False(t, nextCalled)
}
