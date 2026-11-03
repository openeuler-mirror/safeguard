package helpers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCleanup_ReverseOwnershipAndLateRegistration(t *testing.T) {
	ctx, close := WithCleanup(context.Background())
	var order []int
	Own(ctx, func() { order = append(order, 1) })()
	Own(ctx, func() { order = append(order, 2) })()
	require.Empty(t, order)
	close()
	close()
	Own(ctx, func() { order = append(order, 3) })()
	require.Equal(t, []int{2, 1, 3}, order)
}

func TestCleanup_LocalDeferRemainsIdempotent(t *testing.T) {
	count := 0
	close := Own(context.Background(), func() { count++ })
	close()
	close()
	require.Equal(t, 1, count)
}
