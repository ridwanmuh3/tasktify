package handler

import "testing"

func TestReadMemoryRSSKBReturnsProcessRSS(t *testing.T) {
	if got := readMemoryRSSKB(); got <= 0 {
		t.Fatalf("readMemoryRSSKB() = %v, want > 0", got)
	}
}
