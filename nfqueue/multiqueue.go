package nfqueue

import "sync"

type multiQueue struct {
	qs []*nfQueue
}

func NewMultiQueue(min, max uint16) (mq *multiQueue) {
	mq = &multiQueue{make([]*nfQueue, 0, max-min)}
	for i := min; i < max; i++ {
		mq.qs = append(mq.qs, NewNFQueue(i))
	}
	return mq
}

func (mq *multiQueue) Process() <-chan *Packet {
	var (
		wg  sync.WaitGroup
		out = make(chan *Packet, len(mq.qs))
	)
	for _, q := range mq.qs {
		wg.Add(1)
		go func(ch <-chan *Packet) {
			for pkt := range ch {
				out <- pkt
			}
			wg.Done()
		}(q.Process())
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}
func (mq *multiQueue) Destroy() {
	for _, q := range mq.qs {
		q.Destroy()
	}
}
