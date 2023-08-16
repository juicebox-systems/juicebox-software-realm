package main

import (
	"context"
	cryptoRand "crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/golang-jwt/jwt/v4"
	"github.com/juicebox-software-realm/otel"
	"github.com/juicebox-software-realm/providers"
	"github.com/juicebox-software-realm/router"
	"github.com/juicebox-software-realm/types"
)

func init() {
	jwt.DecodeStrict = true
}

func main() {
	idString := flag.String(
		"id",
		"",
		`A 16-byte hex string identifying this realm. (default random)

Note: Changing this id for an existing realm will result in data loss.`,
	)
	port := flag.Uint64(
		"port",
		0,
		"The port to run the server on. (default 8080)",
	)
	providerString := flag.String(
		"provider",
		"",
		`The provider to use. [gcs|aws|mongo|memory] (default "memory")

Some providers take additional configuration via environment variables.

gcp:
    BIGTABLE_INSTANCE_ID = The id of your Bigtable instance in GCP
    GCP_PROJECT_ID       = The id of your project in GCP
aws:
    AWS_REGION_NAME      = The name of the region your AWS instance is in

    Note: AWS uses DynamoDB and assumes you have a table created with a name
          matching your realm id and a partitionKey named recordID.
mongo:
    MONGO_URL = The url to acess your MongoDB instance in the form of:
                mongodb://username:password@host:port/database


    Note: User records are stored in a collection named "userRecords".
    Tenant signing keys are stored in a collection named "tenantSecrets".
memory:
    TENANT_SECRETS = The versioned tenant secrets, in JSON format.
                     For example: {"tenantName":{"1":"tenantSecretKey"}}`,
	)

	flag.Parse()

	var realmID types.RealmID

	// if no id was provided, check if the REALM_ID env
	// variable is set before generating a random one
	if envIDString := os.Getenv("REALM_ID"); envIDString != "" && *idString == "" {
		idString = &envIDString
	}

	if *idString == "" {
		var randomID [16]byte
		_, err := cryptoRand.Read(randomID[:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s, exiting...\n", err)
			os.Exit(1)
		}
		realmID = types.RealmID(randomID)
	} else {
		parsedID, err := hex.DecodeString(*idString)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\n%s, exiting...\n", err)
			os.Exit(2)
		}
		if len(parsedID) != 16 {
			fmt.Fprintf(os.Stderr, "\nInvalid id length %d, exiting...\n", len(parsedID))
			os.Exit(3)
		}
		realmID = types.RealmID([16]byte(parsedID))
	}

	if envPortString := os.Getenv("PORT"); envPortString != "" && *port == 0 {
		envPort, err := strconv.ParseUint(envPortString, 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nInvalid PORT env: %s, exiting...\n", err)
			os.Exit(4)
		}
		port = &envPort
	}

	if *port == 0 {
		*port = 8080
	}

	if envProvider := os.Getenv("PROVIDER"); envProvider != "" && *providerString == "" {
		providerString = &envProvider
	}

	providerName, err := providers.Parse(*providerString)
	if err != nil {
		if *providerString == "" {
			providerName = types.Memory
		} else {
			fmt.Fprintf(os.Stderr, "\n%v, exiting...\n", err)
			os.Exit(5)
		}
	}

	ctx := context.Background()

	tp := otel.InitTraceProvider(ctx, realmID)
	defer func() {
		if err := tp.Shutdown(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Error shutting down tracer provider: %v", err)
		}
	}()

	mp := otel.InitMeterProvider(ctx, realmID)
	defer func() {
		if err := mp.Shutdown(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Error shutting down meter provider: %v", err)
		}
	}()

	provider, err := providers.NewProvider(ctx, providerName, realmID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n%s, exiting...\n", err)
		os.Exit(6)
	}

	router.RunRouter(realmID, provider, *port)
}
