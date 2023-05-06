package main

import (
	"flag"
	"fmt"

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
	disableTls := flag.Bool(
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
		`The provider to use. [gcs|aws|memory] (default "memory")

Some providers take additional configuration via environment variables.

gcp:
	BIGTABLE_INSTANCE_ID = The id of your Bigtable instance in GCP
	GCP_PROJECT_ID = The id of your project in GCP
aws:
	RDS_TABLE_NAME = The name of your RDS table in AWS
memory:
	none`,
	)

	flag.Parse()

	var realmId uuid.UUID

	if *idString == "" {
		randomId, error := uuid.NewRandom()
		if error != nil {
			fmt.Printf("%s, exiting...\n", error)
		}
		realmId = randomId
	} else {
		parsedId, error := uuid.Parse(*idString)
		if error != nil {
			fmt.Printf("\n%s, exiting...\n", error)
			return
		}
		realmId = parsedId
	}

	providerName, error := providers.Parse(*providerString)
	if error != nil {
		if *providerString == "" {
			providerName = types.Memory
		} else {
			fmt.Printf("\n%v, exiting...\n", error)
		}
	}

	provider, error := providers.NewProvider(providerName, realmId)
	if error != nil {
		fmt.Printf("\n%s, exiting...\n", error)
		return
	}

	router.NewRouter(realmId, provider, *disableTls, *port)
}
