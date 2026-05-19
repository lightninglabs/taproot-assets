package rpcserver

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/grpc-ecosystem/grpc-gateway/v2/utilities"
	"google.golang.org/protobuf/proto"
)

const mintBatchesPathPrefix = "/v1/taproot-assets/assets/mint/batches/"

var base64Decoders = []*base64.Encoding{
	base64.StdEncoding,
	base64.URLEncoding,
	base64.RawStdEncoding,
	base64.RawURLEncoding,
}

var normalizedRESTBytesQueryKeys = map[string]struct{}{
	"asset_filter":     {},
	"asset_id":         {},
	"batch_key":        {},
	"group_key":        {},
	"group_key_filter": {},
}

var normalizedRESTHexPathPrefixParams = map[string]string{
	"/v1/taproot-assets/universe/proofs/asset-id/":       "asset_id",
	"/v1/taproot-assets/universe/proofs/group-key/":      "group_key",
	"/v1/taproot-assets/universe/proofs/push/asset-id/":  "asset_id",
	"/v1/taproot-assets/universe/proofs/push/group-key/": "group_key",
	"/v1/taproot-assets/universe/roots/asset-id/":        "asset_id",
	"/v1/taproot-assets/universe/roots/group-key/":       "group_key",
}

type restBytesQueryParser struct {
	defaultParser *runtime.DefaultQueryParser
}

// NewRESTBytesQueryParser creates a query parser that normalizes byte fields.
func NewRESTBytesQueryParser() runtime.QueryParameterParser {
	return &restBytesQueryParser{
		defaultParser: &runtime.DefaultQueryParser{},
	}
}

func (p *restBytesQueryParser) Parse(msg proto.Message, values url.Values,
	filter *utilities.DoubleArray) error {

	err := normalizeRESTBytesQueryValues(values)
	if err != nil {
		return err
	}

	return p.defaultParser.Parse(msg, values, filter)
}

// NewRESTBytesNormalizer normalizes bytes path/query values before dispatch.
func NewRESTBytesNormalizer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := normalizeRESTBytesRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// normalizeRESTBytesRequest normalizes all path and query byte fields in place.
func normalizeRESTBytesRequest(r *http.Request) error {
	err := normalizeRESTBytesPath(r)
	if err != nil {
		return err
	}

	values := r.URL.Query()
	err = normalizeRESTBytesQueryValues(values)
	if err != nil {
		return err
	}

	r.URL.RawQuery = values.Encode()
	return nil
}

// normalizeRESTBytesPath normalizes bytes path segments before routing.
func normalizeRESTBytesPath(r *http.Request) error {
	escapedPath := r.URL.EscapedPath()

	mintBatchPath, shouldNormalize, err := normalizePathParam(
		escapedPath, mintBatchesPathPrefix, "batch_key",
		decodeBase64AnyVariant, base64.URLEncoding.EncodeToString,
		false,
	)
	if err != nil {
		return err
	}
	if shouldNormalize {
		r.URL.Path = mintBatchPath
		r.URL.RawPath = ""
		return nil
	}

	for prefix, paramName := range normalizedRESTHexPathPrefixParams {
		normalizedPath, shouldNormalize, err := normalizePathParam(
			escapedPath, prefix, paramName,
			decodeHexOrBase64AnyVariant, hex.EncodeToString, true,
		)
		if err != nil {
			return err
		}
		if shouldNormalize {
			r.URL.Path = normalizedPath
			r.URL.RawPath = ""
			return nil
		}
	}

	return nil
}

// normalizeRESTBytesQueryValues normalizes known byte query values in place.
func normalizeRESTBytesQueryValues(values url.Values) error {
	for key := range values {
		if !isNormalizedRESTBytesQueryKey(key) {
			continue
		}

		queryValues := values[key]
		for i := range queryValues {
			encodedValue := queryValues[i]
			decodedValue, err := decodeBase64AnyVariant(
				encodedValue,
			)
			if err != nil {
				return fmt.Errorf(
					"invalid query parameter %q: %w",
					key, err,
				)
			}

			queryValues[i] = base64.URLEncoding.EncodeToString(
				decodedValue,
			)
		}

		values[key] = queryValues
	}

	return nil
}

// isNormalizedRESTBytesQueryKey returns true for query keys we normalize.
func isNormalizedRESTBytesQueryKey(key string) bool {
	_, isKnownKey := normalizedRESTBytesQueryKeys[key]
	if isKnownKey {
		return true
	}

	lastDotIdx := strings.LastIndex(key, ".")
	if lastDotIdx == -1 {
		return false
	}

	_, isKnownKey = normalizedRESTBytesQueryKeys[key[lastDotIdx+1:]]
	return isKnownKey
}

// normalizePathParam normalizes the first segment after a path prefix.
func normalizePathParam(escapedPath, prefix, paramName string,
	decoder func(string) ([]byte, error), encoder func([]byte) string,
	allowRemainingPath bool) (string, bool, error) {

	if !strings.HasPrefix(escapedPath, prefix) {
		return "", false, nil
	}

	pathSuffixEscaped := strings.TrimPrefix(escapedPath, prefix)
	if pathSuffixEscaped == "" {
		return "", false, nil
	}

	pathParamEscaped := pathSuffixEscaped
	remainingPath := ""
	if allowRemainingPath {
		pathParamEscaped, remainingPath, _ = strings.Cut(
			pathSuffixEscaped, "/",
		)
	} else if strings.Contains(pathSuffixEscaped, "/") {
		return "", false, nil
	}

	pathParam, err := url.PathUnescape(pathParamEscaped)
	if err != nil {
		return "", false, fmt.Errorf(
			"invalid %s path parameter: %w", paramName, err,
		)
	}

	decodedParam, err := decoder(pathParam)
	if err != nil {
		return "", false, fmt.Errorf(
			"invalid %s path parameter: %w", paramName, err,
		)
	}

	normalizedPath := prefix + encoder(decodedParam)
	if remainingPath != "" {
		normalizedPath += "/" + remainingPath
	}

	return normalizedPath, true, nil
}

// decodeHexOrBase64AnyVariant decodes either hex or any base64 variant.
func decodeHexOrBase64AnyVariant(value string) ([]byte, error) {
	decodedValue, err := hex.DecodeString(value)
	if err == nil {
		return decodedValue, nil
	}

	decodedValue, err = decodeBase64AnyVariant(value)
	if err == nil {
		return decodedValue, nil
	}

	return nil, fmt.Errorf("invalid hex or base64 value")
}

// decodeBase64AnyVariant decodes all supported base64 variants.
func decodeBase64AnyVariant(value string) ([]byte, error) {
	for _, base64Decoder := range base64Decoders {
		decodedValue, err := base64Decoder.DecodeString(value)
		if err == nil {
			return decodedValue, nil
		}
	}

	return nil, fmt.Errorf("invalid base64 value")
}
