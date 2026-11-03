package helpers

import "context"

// StartStage cooperatively cancels between startup operations. It cannot
// interrupt an operation already executing inside the kernel or C library.
func StartStage(ctx context.Context, module, stage string, start func() error) error {
	if err := ctx.Err(); err != nil {
		return During(module, stage, err)
	}
	return During(module, stage, start())
}
