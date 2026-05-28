package service

import (
	"testing"
	"time"
)

func TestTaskTimestampAcceptsStoredSeconds(t *testing.T) {
	seconds := int64(1779970000)

	got := taskTimestamp(seconds).AsTime()
	want := time.Unix(seconds, 0)

	if !got.Equal(want) {
		t.Fatalf("taskTimestamp(%d) = %s, want %s", seconds, got, want)
	}
}

func TestTaskTimestampAcceptsStoredMilliseconds(t *testing.T) {
	milliseconds := int64(1779970000000)

	got := taskTimestamp(milliseconds).AsTime()
	want := time.UnixMilli(milliseconds)

	if !got.Equal(want) {
		t.Fatalf("taskTimestamp(%d) = %s, want %s", milliseconds, got, want)
	}
}
