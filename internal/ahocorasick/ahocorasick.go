package ahocorasick

// Matcher finds every occurrence of a set of byte patterns in one pass
// (Aho-Corasick), so thousands of mapped originals can be searched for in
// gigabytes of output.
type Matcher struct {
	next [][]int32 // next[state] indexed by byteIndex; -1 means none
	fail []int32
	out  [][]int32 // pattern ids ending at state
	lens []int
	// alphabet maps a byte to its column; bytes not in any pattern map to -1.
	alphabet [256]int16
	width    int
}

func New(patterns []string) *Matcher {
	m := &Matcher{}
	for i := range m.alphabet {
		m.alphabet[i] = -1
	}
	for _, p := range patterns {
		for i := 0; i < len(p); i++ {
			if m.alphabet[p[i]] < 0 {
				m.alphabet[p[i]] = int16(m.width)
				m.width++
			}
		}
	}
	m.addState()
	for id, p := range patterns {
		m.lens = append(m.lens, len(p))
		state := int32(0)
		for i := 0; i < len(p); i++ {
			c := m.alphabet[p[i]]
			if m.next[state][c] < 0 {
				m.next[state][c] = m.addState()
			}
			state = m.next[state][c]
		}
		m.out[state] = append(m.out[state], int32(id))
	}
	// Breadth-first: fail links and full goto function.
	queue := []int32{}
	for c := 0; c < m.width; c++ {
		if s := m.next[0][c]; s >= 0 {
			m.fail[s] = 0
			queue = append(queue, s)
		} else {
			m.next[0][c] = 0
		}
	}
	for len(queue) > 0 {
		r := queue[0]
		queue = queue[1:]
		for c := 0; c < m.width; c++ {
			s := m.next[r][c]
			if s < 0 {
				m.next[r][c] = m.next[m.fail[r]][c]
				continue
			}
			queue = append(queue, s)
			f := m.next[m.fail[r]][c]
			m.fail[s] = f
			m.out[s] = append(m.out[s], m.out[f]...)
		}
	}
	return m
}

func (m *Matcher) addState() int32 {
	row := make([]int32, m.width)
	for i := range row {
		row[i] = -1
	}
	m.next = append(m.next, row)
	m.fail = append(m.fail, 0)
	m.out = append(m.out, nil)
	return int32(len(m.next) - 1)
}

// Each calls fn(pattern, start, end) for every occurrence in s.
func (m *Matcher) Each(s string, fn func(id, start, end int)) {
	if m.width == 0 {
		return
	}
	state := int32(0)
	for i := 0; i < len(s); i++ {
		c := m.alphabet[s[i]]
		if c < 0 {
			state = 0
			continue
		}
		state = m.next[state][c]
		for _, id := range m.out[state] {
			end := i + 1
			fn(int(id), end-m.lens[id], end)
		}
	}
}
