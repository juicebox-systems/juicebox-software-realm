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
3. Initialize the provider environment with Terraform
4. Upload the realm software you to your provider

## Tenant Auth Secrets

Realm software is structured to operate in a multi-tenant environment. In order to validate access from different tenants, your realm will need access to the JWT signing key for each tenant you plan to support. You may add support for additional tenants at any time in the future.

In general, regardless of provider, tenant secrets are stored in the following fashion:

```json
{
	"jb-sw-tenant-{{yourTenantName}}": {"{{yourKeyVersionNumber}}": "{{yourSigningKey}}"},
	"jb-sw-tenant-juicebox": {"1": "juicebox-tenant-secret"},
}
```

Note: Tenant names should be unique alphanumeric strings. Key versions should be non-negative integer values.

The realm software will determine which tenant key to validate on a request by accessing the "kid" header field on a received JWT auth token. This field will be provided in the format of `tenantName:1`.

## GCP

The following instructions will help you quickly deploy a realm to Google's App Engine Flex.

Before you begin, setup a project for your realm to run in on console.cloud.google.com and make note of its ID.

Next, setup your project environment with terraform as follows:
```sh
cd gcp
terraform init
terraform plan -var='tenant_secrets={"juicebox":"juicebox-tenant-key","anotherTenant":"another-tenant-key"}'
terraform apply -var='tenant_secrets={"juicebox":"juicebox-tenant-key","anotherTenant":"another-tenant-key"}'
```

Note: you should update the tenant secrets `var` to reflect the actual secrets you wish to support.

After terraform has finished configuring your project environment, you should see an output like follows:
```sh
BIGTABLE_INSTANCE_ID = "jb-sw-realms"
GCP_PROJECT_ID = "your-project-id"
REALM_ID = "99b2da84-b707-6203-dc35-804bbbcb8cba"
SERVICE_ACCOUNT = "jb-sw-realms@your-project-id.iam.gserviceaccount.com"
```

Open the `app.yaml` in this directory and configure it with these values where appropriate, for example:
Replace `{{YOUR_BIGTABLE_INSTANCE_ID}}` with `jb-sw-realms`.

Finally, you can deploy the realm software by running the following command from the root of the repo:
```sh
gcloud app deploy --project {{YOUR_GCP_PROJECT_ID}}
```

Note: you will need to have the `gcloud` command line tools installed to execute this command. You can find instructions on installing these [here](https://cloud.google.com/sdk/docs/install).

This may take a few minutes, but upon success you should be able to access your realm at:
https://{{YOUR_GCP_PROJECT_ID}}.wl.r.appspot.com

If all was successful, you'll see a page render that looks something like:
```json
{"realmID":"99b2da84-b707-6203-dc35-804bbbcb8cba"}
```

If you wish to configure a custom domain for your new realm, visit:
https://console.cloud.google.com/appengine/settings/domains
