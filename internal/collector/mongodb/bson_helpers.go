package mongodb

// asInt converts a BSON value to int. Handles int32, int64, float64, and nil.
func asInt(v interface{}) int32 {
	switch val := v.(type) {
	case int32:
		return val
	case int64:
		return int32(val)
	case float64:
		return int32(val)
	case nil:
		return 0
	default:
		return 0
	}
}

// asInt64 converts a BSON value to int64.
func asInt64(v interface{}) int64 {
	switch val := v.(type) {
	case int32:
		return int64(val)
	case int64:
		return val
	case float64:
		return int64(val)
	case nil:
		return 0
	default:
		return 0
	}
}

// asFloat converts a BSON value to float64.
func asFloat(v interface{}) float64 {
	switch val := v.(type) {
	case int32:
		return float64(val)
	case int64:
		return float64(val)
	case float64:
		return val
	case nil:
		return 0
	default:
		return 0
	}
}

// asString converts a BSON value to string.
func asString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// Exported wrappers for external tests.

func AsIntExported(v interface{}) int32     { return asInt(v) }
func AsInt64Exported(v interface{}) int64   { return asInt64(v) }
func AsFloatExported(v interface{}) float64 { return asFloat(v) }
func AsStringExported(v interface{}) string { return asString(v) }
