package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/laurentpellegrino/tundler/internal/config"
	"github.com/laurentpellegrino/tundler/internal/httpapi"
	"github.com/laurentpellegrino/tundler/internal/manager"
	"github.com/laurentpellegrino/tundler/internal/provider"
	_ "github.com/laurentpellegrino/tundler/internal/provider/register"
	"github.com/laurentpellegrino/tundler/internal/telemetry"
)

func main() {
	home, _ := os.UserHomeDir()
	cfgPath := filepath.Join(home, ".config", "tundler", "tundler.yaml")

	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.StringVar(&cfgPath, "c", cfgPath, "configuration file path")
	fs.StringVar(&cfgPath, "config", cfgPath, "configuration file path (long)")
	_ = fs.Parse(os.Args[1:])

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("cannot load config: %v", err)
	}

	port := flag.String("l", "4242", "listen port")
	login := flag.String("login", "", "comma-separated providers to login at startup (\"all\" for every provider)")
	flag.StringVar(&cfgPath, "c", cfgPath, "configuration file path")
	flag.StringVar(&cfgPath, "config", cfgPath, "configuration file path (long)")
	debug := cfg.Debug
	flag.BoolVar(&debug, "d", debug, "enable debug logging")
	flag.BoolVar(&debug, "debug", debug, "enable debug logging (long)")
	enableTelemetry := cfg.Telemetry
	flag.BoolVar(&enableTelemetry, "telemetry", enableTelemetry, "enable anonymous telemetry")
	flag.Parse()

	telemetry.SetEnabled(enableTelemetry)
	mgr := manager.New(debug, providerLocations(cfg))

	if *login != "" {
		ctx := context.Background()
		if *login == "all" {
			if err := mgr.Login(ctx, ""); err != nil {
				log.Printf("login all providers failed: %v", err)
			}
		} else {
			for _, name := range strings.Split(*login, ",") {
				name = strings.TrimSpace(name)
				if name == "" {
					continue
				}
				if err := mgr.Login(ctx, name); err != nil {
					log.Printf("login %s failed: %v", name, err)
				}
			}
		}
	}

	mux := httpapi.Router(mgr)
	addr := fmt.Sprintf(":%s", *port)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("tundler-api listening on %s (debug=%v, telemetry=%v)", addr, debug, enableTelemetry)
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
