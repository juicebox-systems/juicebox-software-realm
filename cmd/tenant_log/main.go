package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/juicebox-systems/juicebox-software-realm/otel"
	"github.com/juicebox-systems/juicebox-software-realm/pubsub"
	"github.com/juicebox-systems/juicebox-software-realm/router"
	"github.com/juicebox-systems/juicebox-software-realm/secrets"
	"github.com/juicebox-systems/juicebox-software-realm/types"
)

// / This is a stand-alone service for the tenant log API. It's used by the HSM realm.

func main() {
	idString := flag.String(
		"id",
		"",
		`A 16-byte hex string identifying this realm.`,
	)
	port := flag.Uint64(
		"port",
		0,
		"The port to run the server on. (default 8080)",
	)
	flag.Parse()

	if envPortString := os.Getenv("PORT"); envPortString != "" && *port == 0 {
		envPort, err := strconv.ParseUint(envPortString, 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nInvalid PORT env: %s, exiting...\n", err)
			os.Exit(1)
		}
		*port = envPort
	}
	if *port == 0 {
		*port = 8080
	}
	// if no id was provided, check if the REALM_ID env
	if envIDString := os.Getenv("REALM_ID"); envIDString != "" && *idString == "" {
		*idString = envIDString
	}
	parsedID, err := hex.DecodeString(*idString)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n%s, exiting...\n", err)
		os.Exit(2)
	}
	if len(parsedID) != 16 {
		fmt.Fprintf(os.Stderr, "\nInvalid realm id length %d, exiting...\n", len(parsedID))
		os.Exit(3)
	}
	realmID := types.RealmID(parsedID)

	ctx := context.Background()
	tp := otel.InitTraceProvider(ctx, "tenant-log", realmID)
	defer func() {
		if err := tp.Shutdown(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Error shutting down tracer provider: %v\n", err)
		}
	}()

	mp := otel.InitMeterProvider(ctx, "tenant-log", realmID)
	defer func() {
		if err := mp.Shutdown(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Error shutting down meter provider: %v\n", err)
		}
	}()

	secretsManager, err := secrets.NewGcpSecretsManager(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing secrets manager:  %v\n", err)
		os.Exit(6)
	}
	pubSub, err := pubsub.NewPubSub(ctx, types.GCP, realmID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing pub/sub connection: %v\n", err)
		os.Exit(7)
	}
	e := router.NewTenantAPIServer(realmID, secretsManager, pubSub)
	e.Logger.Fatal(e.Start(fmt.Sprintf(":%d", *port)))
}
