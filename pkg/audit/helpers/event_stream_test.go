package helpers

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNextEvent_SkipsEmptyFramesWithoutLosingLaterData(t *testing.T) {
	events := make(chan []byte, 3)
	events <- nil
	events <- []byte{}
	events <- []byte{1, 2, 3}
	close(events)
	frame, open := NextEvent(events)
	require.True(t, open)
	require.Equal(t, []byte{1, 2, 3}, frame)
	frame, open = NextEvent(events)
	require.False(t, open)
	require.Nil(t, frame)
}
