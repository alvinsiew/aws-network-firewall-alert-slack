# aws-network-firewall-alert-slack
aws-network-firewall-alert-slack is a lambda that trigger slack notification when network fire rule detected a block ip.


## Self-compile

```bash
# Linux
env GOOS=linux CGO_ENABLED=0 go build main.go -o build/main
```

## Zip binary for upload to AWS Lambda

```bash
cd build
zip function.zip main
```

## Create the environment variables
![Optional Text](../main/screenshots/lambda_env.jpeg)
CHANNEL: Slack channel name \
KMS_ARN: KMS ARN of KMS that is used to encrypt CHANNEL, USERNAME and WEBHOOKURL \
USERNAME: Slack username (can be any name) \
WEBHOOKURL: Slack web hook url

Note:\
CHANNEL, USERNAME and WEBHOOKURL have to be encrypted.\
KMS_ARN should not be encrypted