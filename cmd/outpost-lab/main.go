// outpost-lab runs synthetic feasibility experiments. It is not a backup service.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	phase := flag.String("phase", "", "prepare, maintenance or verify")
	work := flag.String("workdir", "", "new, dedicated prepare directory")
	kit := flag.String("kit", "", "standalone kit repository (verify)")
	key := flag.String("key", "", "recovery password file (verify)")
	out := flag.String("output", "", "new restore directory (verify)")
	expected := flag.String("expected", "", "synthetic test oracle; not a restore dependency")
	versions := flag.String("versions", "v1,v2", "exact expected fixture versions: v1,v2 or v2")
	restic := flag.String("restic", "restic", "restic 0.19.1 executable")
	flag.Parse()
	// Fixed fault injection for the native producer-status experiment: emit a
	// nonempty prefix, then fail. No repository or real source is accessed.
	if *phase == "failed-producer" {
		_, _ = os.Stdout.Write(make([]byte, 64<<10))
		os.Exit(3)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var result any
	var err error
	switch *phase {
	case "prepare":
		result, err = prepare(ctx, *restic, *work)
	case "verify":
		result, err = verify(ctx, *restic, *kit, *key, *out, *expected, *versions)
	case "maintenance":
		result, err = maintenance(ctx, *restic, *kit, *key, *work)
	default:
		err = fmt.Errorf("choose --phase prepare, maintenance or verify; synthetic data only")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "outpost-lab:", err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "outpost-lab: result write failed")
		os.Exit(1)
	}
}
