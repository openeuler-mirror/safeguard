package helpers

import "fmt"

type Link interface{ Destroy() error }

// AttachAll rolls back only links created by this attempt, in reverse order.
// Successfully attached links remain owned by the BPF module.
func AttachAll(names []string, attach func(string) (Link, error)) error {
	var links []Link
	for _, name := range names {
		link, err := attach(name)
		if err != nil {
			failure := fmt.Errorf("attach %s: %w", name, err)
			for i := len(links) - 1; i >= 0; i-- {
				if cleanupErr := links[i].Destroy(); cleanupErr != nil {
					failure = fmt.Errorf("%w; rollback: %v", failure, cleanupErr)
				}
			}
			return failure
		}
		links = append(links, link)
	}
	return nil
}
