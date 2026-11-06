// Package pipeline processes the lines of large files on several cores while
// keeping their order: a file is cut into blocks of whole lines, blocks are
// processed by a shared pool of workers, and results are handed back in the
// order of the blocks.
package pipeline

import (
	"bufio"
	"bytes"
	"io"
	"sync"
)

// BlockSize is the target size of a block; a block always ends at a line end.
const BlockSize = 1 << 20

// Pool runs tasks on a fixed number of goroutines, shared by all files.
type Pool struct {
	tasks chan func()
	wg    sync.WaitGroup
	n     int
}

func NewPool(n int) *Pool {
	if n < 1 {
		n = 1
	}
	p := &Pool{tasks: make(chan func()), n: n}
	for i := 0; i < n; i++ {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for task := range p.tasks {
				task()
			}
		}()
	}
	return p
}

// Size is the number of workers.
func (p *Pool) Size() int { return p.n }

// Go runs task on a worker; it blocks until a worker takes it.
func (p *Pool) Go(task func()) { p.tasks <- task }

// Do runs task on a worker and waits for it.
func (p *Pool) Do(task func()) {
	done := make(chan struct{})
	p.tasks <- func() {
		defer close(done)
		task()
	}
	<-done
}

func (p *Pool) Close() {
	close(p.tasks)
	p.wg.Wait()
}

type result[T any] struct {
	value T
	err   error
}

// Lines cuts r into blocks of whole lines, runs work on each block in the
// pool and calls emit with the results in input order. firstLine is the
// 1-based number of the block's first line. The first error from work, emit
// or reading stops the file and is returned.
func Lines[T any](p *Pool, r io.Reader, work func(block []byte, firstLine int) (T, error), emit func(T) error) error {
	queue := make(chan chan result[T], p.Size()+2)
	done := make(chan struct{})
	readErr := make(chan error, 1)
	go func() {
		defer close(queue)
		br := bufio.NewReaderSize(r, 1<<16)
		line := 1
		for {
			block, err := readBlock(br)
			if len(block) > 0 {
				ch := make(chan result[T], 1)
				first := line
				line += bytes.Count(block, []byte{'\n'})
				select {
				case queue <- ch:
				case <-done:
					readErr <- nil
					return
				}
				b := block
				p.Go(func() {
					v, e := work(b, first)
					ch <- result[T]{v, e}
				})
			}
			if err != nil {
				if err == io.EOF {
					err = nil
				}
				readErr <- err
				return
			}
		}
	}()
	var firstErr error
	for ch := range queue {
		res := <-ch
		if firstErr != nil {
			continue
		}
		if res.err != nil {
			firstErr = res.err
		} else if err := emit(res.value); err != nil {
			firstErr = err
		}
		if firstErr != nil {
			close(done)
		}
	}
	if err := <-readErr; firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// readBlock reads about BlockSize bytes and completes the last line. It
// returns the reader's own error: a truncated gzip stream reports
// io.ErrUnexpectedEOF, which must not be taken for the end of the file.
func readBlock(br *bufio.Reader) ([]byte, error) {
	buf := make([]byte, 0, BlockSize+4096)
	for len(buf) < BlockSize {
		n, err := br.Read(buf[len(buf):BlockSize])
		buf = buf[:len(buf)+n]
		if err != nil {
			return buf, err
		}
	}
	rest, err := br.ReadBytes('\n')
	return append(buf, rest...), err
}

// EachLine calls fn for every line of block, newline included.
func EachLine(block []byte, fn func(line []byte) error) error {
	for len(block) > 0 {
		i := bytes.IndexByte(block, '\n')
		if i < 0 {
			return fn(block)
		}
		if err := fn(block[:i+1]); err != nil {
			return err
		}
		block = block[i+1:]
	}
	return nil
}
