package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/laurentpellegrino/tundler/internal/config"
	"github.com/laurentpellegrino/tundler/internal/httpapi"
	"github.com/laurentpellegrino/tundler/internal/manager"
	"github.com/laurentpellegrino/tundler/internal/provider"
	_ "github.com/laurentpellegrino/tundler/internal/provider/register"
)

func main() {
	cfg, err := config.Load("/home/tundler/tundler.yaml")
	if err != nil {
		log.Fatalf("cannot load config: %v", err)
	}

	debug := cfg.Debug
	flag.BoolVar(&debug, "d", debug, "enable debug logging")
	flag.BoolVar(&debug, "debug", debug, "enable debug logging (long)")
	port := flag.String("l", "4242", "listen port")
	flag.Parse()

	mgr := manager.New(debug, providerLocations(cfg))
	mux := httpapi.Router(mgr)
	addr := fmt.Sprintf(":%s", *port)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("tundler-api listening on %s (debug=%v)", addr, *debug)
	log.Fatal(srv.ListenAndServe())
}

func providerLocations(cfg *config.Config) map[string][]string {
	ctx := context.Background()
	out := make(map[string][]string, len(cfg.Providers))
	for name, p := range cfg.Providers {
		prov, ok := provider.Registry[name]
		if !ok {
			log.Printf("[config] unknown provider %q ignored", name)
			continue
		}
		if len(p.Locations) == 0 {
			continue
		}
		valid := make(map[string]struct{})
		for _, loc := range prov.Locations(ctx) {
			valid[loc] = struct{}{}
		}
		for _, loc := range p.Locations {
			if _, ok := valid[loc]; ok {
				out[name] = append(out[name], loc)
			} else {
				log.Printf("[config] provider %s: unknown location %s ignored", name, loc)
			}
		}
	}
	return out
}
