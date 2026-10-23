package proxy

import (
	"unicode/utf8"
)

func utf8Valid(data []byte) bool {
	return utf8.Valid(data)
}
