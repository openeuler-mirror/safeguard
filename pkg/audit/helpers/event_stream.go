package helpers

// NextEvent distinguishes a closed stream from an empty frame. Empty frames
// must not turn a parser's EOF into premature termination of a live stream.
func NextEvent(events <-chan []byte) ([]byte, bool) {
	for frame := range events {
		if len(frame) != 0 {
			return frame, true
		}
	}
	return nil, false
}
