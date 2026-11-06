package pipeline

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestLinesKeepsOrderAndLineNumbers(t *testing.T) {
	var b strings.Builder
	for i := 1; i <= 300000; i++ {
		fmt.Fprintf(&b, "line %d %s\n", i, strings.Repeat("x", i%50))
	}
	b.WriteString("last line without newline")
	p := NewPool(8)
	defer p.Close()
	var out strings.Builder
	next := 1
	err := Lines(p, strings.NewReader(b.String()), func(block []byte, first int) (string, error) {
		return fmt.Sprintf("%d:", first) + string(block), nil
	}, func(s string) error {
		i := strings.IndexByte(s, ':')
		if s[:i] != fmt.Sprint(next) {
			return fmt.Errorf("block starts at line %s, want %d", s[:i], next)
		}
		next += strings.Count(s[i+1:], "\n")
		out.WriteString(s[i+1:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != b.String() {
		t.Fatal("output differs from input")
	}
}

func TestLinesStopsOnError(t *testing.T) {
	p := NewPool(4)
	defer p.Close()
	input := strings.Repeat(strings.Repeat("y", 1000)+"\n", 20000)
	boom := errors.New("boom")
	calls := 0
	err := Lines(p, strings.NewReader(input), func(block []byte, first int) (int, error) {
		if first > 1 {
			return 0, boom
		}
		return 1, nil
	}, func(int) error { calls++; return nil })
	if !errors.Is(err, boom) || calls != 1 {
		t.Fatalf("err %v, calls %d", err, calls)
	}
}
