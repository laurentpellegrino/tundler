package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/laurentpellegrino/tundler/internal/httpapi"
	"github.com/laurentpellegrino/tundler/internal/manager"
	_ "github.com/laurentpellegrino/tundler/internal/provider/register"
)

func main() {
	port := flag.String("l", "4242", "listen port")
	debug := flag.Bool("d", false, "enable debug logging")
	flag.BoolVar(debug, "debug", false, "enable debug logging (long)")
	flag.Parse()

	mgr := manager.New(*debug)
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
