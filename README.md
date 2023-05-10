# Juicebox Software Realm

This project contains all the software necessary to run a Juicebox Software Realm on the hosting provider of your choice.

We recommend adding at least one software backed realm to your configuration alongside Juicebox's hardware backed realms. Utilizing realms hosted in different cloud providers and maintained by different authorities – in addition to Juicebox's hardware backed realms – can increase the security of your user secrets. With this diversity in your configuration, you would have to compromise at least `recover_threshold` different realm providers before you could even attempt to recover a secret (and you'd _still_ have to gain access to their PIN in order to decrypt the secret).

## Usage

```
Usage of jb-sw-realm:
  -disable-tls
    	Set this flag to insecurely run the server without TLS.
  -id string
    	A 16-byte hex string identifying this realm. (default random)

    	We recommend using a UUID, but any 16-byte hex string is valid.

    	Note: Changing this id for an existing realm will result in data loss.
  -port int
    	The port to run the server on. (default 443)
  -provider string
    	The provider to use. [gcs|aws|mongo|memory] (default "memory")

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
    	                     For example: {"tenantName":{"1":"tenantSecretKey"}}
```

Compile the Juicebox Software Realm with `go build -o jb-sw-realm` or compile and run with `go run main.go`.

To quickly spin up a local realm for testing, you can run:

 ```sh
TENANT_SECRETS='{"test":{"1":"an-auth-token-key"}}' jb-sw-realm -disable-tls -port 8080
 ```

## Running a Realm

This software is setup to be portable to the cloud provider of your choice.

In order to run a realm you will generally need to:
1. Clone this repo
2. Choose a provider to manage your data
3. Build a docker image configured with that provider
4. Run the docker image within the provider of your choice, such as a GCP VM or AWS EC2
5. Instantiate your database, such as GCP Bigtable or AWS DynamoDB
6. Store your tenant secrets #todo explain more about this
7. Configure your DNS to point to your instance

For more detailed instructions for the provider of your choice, see [GCP](GCP.md) or [AWS](#todo).
