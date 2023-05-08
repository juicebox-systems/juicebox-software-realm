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
                      matching your realm id and a partitionKey named recordId.
        mongo:
                MONGO_URL = The url to acess your MongoDB instance in the form of:
                            mongodb://username:password@host:port/database_name

                Note: User records are stored in a collection named "userRecords".
	            Tenant signing keys are stored in a collection named "tenantSecrets".
```

Compile the Juicebox Software Realm with `go build -o jb-sw-realm` or compile and run with `go run main.go`.

To quickly spin up a local realm for testing, you can run:

 ```sh
jb-sw-realm -disable-tls -port 8080
 ```

## Hosting a Realm

This software is setup to be portable to the cloud provider of your choice. Follow the instructions below to get a realm running in minutes.

### Clone This Repo

```sh
git clone https://github.com/Loam-Security/juicebox-software-realm.git
cd juicebox-software-realm
```

### Install Docker

The software realm runs in a docker containerized environment.

If you don't already have docker setup on your machine, install it by running the following commands.

On Mac, run:
```sh
brew install --cask docker
open /Applications/Docker.app
```

On Linux, run:
```sh
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
```

### Generate a Realm Id

Every realm needs a unique 16-byte identifier. We recommend using a UUID for your realm.

You can generate one as follows:

```sh
REALM_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
echo $REALM_ID
```

Remember this Realm Id, as you'll need it to configure any connecting clients.

### Choose Your Provider

#### Google Cloud Services

##### Install `gcloud` CLI

To setup a realm on GCP we use the `gcloud` CLI tools.

To ensure you have them installed..

On Mac, run:
```sh
brew install google-cloud-sdk
```

On Linux, run:
```sh
sudo apt-get install google-cloud-cli
```

Then, authenticate with your google account that you plan to use with GCS.

```sh
gcloud auth login
```

##### Prepare a Project

All the following steps operate within the scope of a GCS project.

If you need to create a new project, you can do so by visiting:
https://console.cloud.google.com/projectcreate

In your shell, store the ID of the project you've created:
```sh
GCP_PROJECT_ID=jb-sw-realm
gcloud config set project ${GCP_PROJECT_ID}
```

##### Prepare a Container Image

The software you'll be deploying is containerized, so you'll need to build and upload the docker container image that the server will run.

First, create a docker artifact repository to upload your image to:
```sh
REALM_LOCATION=us-west1
REPOSITORY_NAME=docker-images
gcloud artifacts repositories create ${REPOSITORY_NAME} \
    --repository-format=docker \
    --location=${REALM_LOCATION}
```

Next, build, tag, and upload the docker image to the repository you just created:
```sh
IMAGE_NAME=jb-sw-realm-image
gcloud auth configure-docker ${REALM_LOCATION}-docker.pkg.dev
docker build \
    --platform=linux/amd64 \
    --build-arg PROVIDER=gcp \
    -t ${IMAGE_NAME} .
docker tag ${IMAGE_NAME} ${REALM_LOCATION}-docker.pkg.dev/${GCP_PROJECT_ID}/${REPOSITORY_NAME}/${IMAGE_NAME}
docker push ${REALM_LOCATION}-docker.pkg.dev/${GCP_PROJECT_ID}/${REPOSITORY_NAME}/${IMAGE_NAME}
```

##### Create a BigTable Instance

The secret shares that a user sends to your realm will be persisted in a BigTable instance. You can share an existing BigTable instance or create a new one for this purpose.

Secrets will be stored in a table with the same name as your `$REALM_ID`.

You can create a new instance to use with the following command:
```sh
BIGTABLE_INSTANCE_ID=jb-sw-realm-bigtable-instance
BIGTABLE_CLUSTER=${BIGTABLE_INSTANCE_ID}-cluster
gcloud bigtable instances create ${BIGTABLE_INSTANCE_ID} \
    --display-name="Juicebox Software Realm" \
    --cluster-config=id=${BIGTABLE_CLUSTER},zone=${REALM_LOCATION}-a
```

##### Configure Your Firewall

The realm software exposes a TLS webserver on port `443` that should be accessible to the internet.

You can run the following command to setup a firewall rule that enables access to `443` for any servers in your project with the tag `jb-sw-realm`.

```sh
REALM_TAG=jb-sw-realm
gcloud compute firewall-rules create allow-jb-sw-realm-https \
	--direction=INGRESS \
	--priority=1000 \
	--network=default \
	--action=ALLOW \
	--rules=tcp:443 \
	--target-tags=${REALM_TAG} \
	--source-ranges=0.0.0.0/0
```

##### Create a New Compute Instance

Now that you have everything prepared, you can create a new containerized compute instance that will automatically run the docker image we uploaded earlier.

First, we need to setup a static IP for our instance. We'll later map this IP to the domain user's would configured in their SDK:
```sh
INSTANCE_NAME=jb-sw-realm-${REALM_ID}
gcloud compute addresses create ${INSTANCE_NAME} \
    --region ${REALM_LOCATION}
```

Next, create a new containerized instance that loads the docker image you previously uploaded by running the following command.

```sh
gcloud compute instances create-with-container ${INSTANCE_NAME} \
    --container-image ${REALM_LOCATION}-docker.pkg.dev/${GCP_PROJECT_ID}/${REPOSITORY_NAME}/${IMAGE_NAME} \
    --container-env GCP_PROJECT_ID=${GCP_PROJECT_ID},BIGTABLE_INSTANCE_ID=${BIGTABLE_INSTANCE_ID},REALM_ID=${REALM_ID} \
    --tags ${REALM_TAG} \
    --address ${INSTANCE_NAME} \
    --machine-type n2d-standard-2 \
    --zone us-west1-a \
    --maintenance-policy TERMINATE \
    --scopes https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/bigtable.data,https://www.googleapis.com/auth/bigtable.admin
```

Once the instance is created, you should see an output like the following:
```sh
Created [https://www.googleapis.com/compute/v1/projects/${GCP_PROJECT_ID}/zones/${REALM_LOCATION}-a/instances/${INSTANCE_NAME}].
NAME             ZONE        MACHINE_TYPE    PREEMPTIBLE  INTERNAL_IP  EXTERNAL_IP    STATUS
${INSTANCE_NAME} us-west1-a  n2d-standard-2               10.138.0.13  34.82.111.251  RUNNING
```

Make note of the external IP address, as you'll use this in the [final steps](#final-steps) when configuring your DNS servers.

_*Note: if you later wish to update this container, you can repeat the steps to build, tag, and upload a new docker image. This will restart your instance, but you should not lose any stored data. Always check the release notes before upgrade to verify if there are any other caveats.*_

Then, run:
```sh
gcloud compute instances update-container ${INSTANCE_NAME} \
	--container-image=${REALM_LOCATION}-docker.pkg.dev/${GCP_PROJECT_ID}/${REPOSITORY_NAME}/${IMAGE_NAME}
```

##### Store Your Auth Token Signing Key

Now that you have a server running, you need to configure it to allow client authentication.

Clients will authenticate with your realm using a signed JWT token. These tokens are scoped by the `tenant` that issued their token.

In order for you to validate these tokens, you will need to upload the signing key for each tenant you support. These keys should be stored as secrets with the naming scheme `tenant-{name}` with the version the tenant will specify in their `kid`.

The code below demonstrastes how to upload one key for a tenant named `juicebox` stored in `signing.key`.

```sh
TENANT_NAME=juicebox
gcloud secrets create tenant-${TENANT_NAME} --data-file=signing.key
```

##### Configure IAM Permissions

Finally, you need to grant your server permissions to access both the Bigtable instance you created and any secrets you have registered.

To grant access to Bigtable, you can run the following command:

```sh
SERVICE_ACCOUNT_EMAIL=$(gcloud compute instances describe ${INSTANCE_NAME} --format='value(serviceAccounts[].email)')
gcloud bigtable instances add-iam-policy-binding ${BIGTABLE_INSTANCE_ID} \
    --member=serviceAccount:${SERVICE_ACCOUNT_EMAIL} \
        --role=roles/bigtable.admin
```

And to grant access to the secret you created, you can run the following command:

```sh
gcloud secrets add-iam-policy-binding tenant-${TENANT_NAME} \
    --member=serviceAccount:${SERVICE_ACCOUNT_EMAIL} \
    --role=roles/secretmanager.secretAccessor
```

_*Note: Remember, you'll need to grant access to each tenant secret you uploaded.*_

#### Final Steps

##### Configuring your DNS

Im order for clients to access your server, you'll need to configure a domain record to point at it. The simplest way to do this is by configuring new A record pointing to your realm's external server IP, which should look something similar to the following:

```dns
A
your.subdomain
34.83.72.169
```

##### Checking for Life

Now, open `https://your.subdomain.domain.tld/` in your browser (using the domain you configured in the previous step).

_*Note: It may take a few moments to load as it acquires a TLS certifcate for your domain.*_

If everything was successful, you should see a page like the following:
```json
{"realm_id":"${REALM_ID}"}
```

Congratulations! You are now hosting a Juicebox Software Realm.

You can configure your SDK using your URL and `$REALM_ID` like follows:
```swift
let yourNewRealm = Realm(
    id: UUID(string: "${REALM_ID}")!,
    address: URL(string: "https://your.subdomain.domain.tld/")!
)
```

For more detailed instructions on configuring and using the SDK, visit the SDK repo.
