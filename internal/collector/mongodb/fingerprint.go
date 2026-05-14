package mongodb

import (
	"encoding/hex"
	"hash/fnv"
	"sort"
	"strings"
)

// NormalizeQuery replaces literal values with ? and sorts keys alphabetically.
// Input: {name: "John", age: {$gt: 30}} -> Output: {age:{$gt:?},name:?}
func NormalizeQuery(doc map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(doc))
	for k, v := range doc {
		result[k] = normalizeValue(v)
	}
	return result
}

func normalizeValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		return NormalizeQuery(val)
	case []interface{}:
		result := make([]interface{}, len(val))
		for i := range val {
			result[i] = "?" // Replace all array elements with ?
		}
		return result
	case string, int, int32, int64, float64, bool:
		return "?"
	case nil:
		return "?"
	default:
		return "?"
	}
}

// FingerprintQuery produces a deterministic hash for a normalized query shape.
func FingerprintQuery(query map[string]interface{}) string {
	normalized := NormalizeQuery(query)
	canonical := canonicalize(normalized)
	h := fnv.New64a()
	h.Write([]byte(canonical))
	return hex.EncodeToString(h.Sum(nil))
}

// canonicalize produces a deterministic string representation by sorting keys.
func canonicalize(v interface{}) string {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = k + ":" + canonicalize(val[k])
		}
		return "{" + strings.Join(parts, ",") + "}"
	case []interface{}:
		parts := make([]string, len(val))
		for i, elem := range val {
			parts[i] = canonicalize(elem)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case string:
		return `"` + val + `"`
	default:
		return "?"
	}
}
