package config

import "strconv"

// Pagination holds limit/offset parameters for list queries.
type Pagination struct {
	Limit  int
	Offset int
}

// ParsePagination extracts limit and offset from string parameters.
func ParsePagination(limitStr, offsetStr string) Pagination {
	p := Pagination{Limit: 100, Offset: 0}
	if v, err := strconv.Atoi(limitStr); err == nil && v > 0 && v <= 1000 {
		p.Limit = v
	}
	if v, err := strconv.Atoi(offsetStr); err == nil && v >= 0 {
		p.Offset = v
	}
	return p
}
