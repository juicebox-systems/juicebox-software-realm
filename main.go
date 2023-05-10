package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/juicebox-software-realm/providers"
	"github.com/juicebox-software-realm/router"
	"github.com/juicebox-software-realm/types"
)

func main() {
	idString := flag.String(
		"id",
		"",
		`A 16-byte hex string identifying this realm. (default random)

We recommend using a UUID, but any 16-byte hex string is valid.

Note: Changing this id for an existing realm will result in data loss.`,
	)
	disableTLS := flag.Bool(
		"disable-tls",
		false,
		"Set this flag to insecurely run the server without TLS.",
	)
	port := flag.Int(
		"port",
		443,
		"The port to run the server on.",
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

	var realmID uuid.UUID

	// if no id was provided, check if the REALM_ID env
	// variable is set before generating a random one
	if envIDString := os.Getenv("REALM_ID"); envIDString != "" && *idString == "" {
		idString = &envIDString
	}

	if *idString == "" {
		randomID, err := uuid.NewRandom()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s, exiting...\n", err)
			os.Exit(1)
		}
		realmID = randomID
	} else {
		parsedID, err := uuid.Parse(*idString)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\n%s, exiting...\n", err)
			os.Exit(2)
		}
		realmID = parsedID
	}

	providerName, err := providers.Parse(*providerString)
	if err != nil {
		if *providerString == "" {
			providerName = types.Memory
		} else {
			fmt.Fprintf(os.Stderr, "\n%v, exiting...\n", err)
			os.Exit(3)
		}
	}

	provider, err := providers.NewProvider(providerName, realmID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n%s, exiting...\n", err)
		os.Exit(4)
	}

	router.RunRouter(realmID, provider, *disableTLS, *port)
}
