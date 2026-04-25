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
	"github.com/laurentpellegrino/tundler/internal/plugin"
	_ "github.com/laurentpellegrino/tundler/internal/plugin/register"
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
	pluginManager, err := plugin.New(cfg.Plugins)
	if err != nil {
		log.Fatalf("cannot load plugins: %v", err)
	}
	mgr := manager.New(debug, providerFilters(cfg), pluginManager)

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

	// Self-restart on sustained provider wedge. Complements the /livez
	// probe (which keeps kubelet from SIGKILLing on transient CLI
	// slowness): a provider whose status query times out for 5+ minutes
	// straight is judged broken, and tundler exits so kubelet recreates
	// the container with fresh daemons.
	mgr.StartWatchdog(context.Background())

	mux := httpapi.Router(mgr, pluginManager)
	addr := fmt.Sprintf(":%s", *port)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("tundler-api listening on %s (debug=%v, telemetry=%v)", addr, debug, enableTelemetry)
	log.Fatal(srv.ListenAndServe())
}

func providerFilters(cfg *config.Config) map[string]manager.LocationFilter {
	ctx := context.Background()
	out := make(map[string]manager.LocationFilter, len(cfg.Providers))
	for name, p := range cfg.Providers {
		prov, ok := provider.Registry[name]
		if !ok {
			log.Printf("[config] unknown provider %q ignored", name)
			continue
		}
		if len(p.Locations.Allow) == 0 && len(p.Locations.Block) == 0 {
			continue
		}
		// Some providers (e.g. ExpressVPN v5) only report locations
		// when logged in. Skip validation and trust the config when the
		// provider cannot supply its location list yet.
		known := prov.Locations(ctx)
		if len(known) == 0 || !prov.LoggedIn(ctx) {
			out[name] = manager.LocationFilter{
				Allow: append([]string(nil), p.Locations.Allow...),
				Block: append([]string(nil), p.Locations.Block...),
			}
			continue
		}
		valid := make(map[string]struct{}, len(known))
		for _, loc := range known {
			valid[loc] = struct{}{}
		}
		var f manager.LocationFilter
		for _, loc := range p.Locations.Allow {
			if _, ok := valid[loc]; ok {
				f.Allow = append(f.Allow, loc)
			} else {
				log.Printf("[config] provider %s: unknown allow location %s ignored", name, loc)
			}
		}
		for _, loc := range p.Locations.Block {
			if _, ok := valid[loc]; ok {
				f.Block = append(f.Block, loc)
			} else {
				log.Printf("[config] provider %s: unknown block location %s ignored", name, loc)
			}
		}
		out[name] = f
	}
	return out
}
