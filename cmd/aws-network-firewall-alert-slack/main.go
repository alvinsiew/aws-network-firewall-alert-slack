package main

import (
	"aws-network-firewall-alert-slack/internal/awsmod"
	"aws-network-firewall-alert-slack/internal/slack"
	"context"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"log"
	"os"
	"strings"
)

var encryptedChannel string = os.Getenv("CHANNEL")
var encryptedUserName string = os.Getenv("USERNAME")
var encryptedWebHookURL string = os.Getenv("WEBHOOKURL")

//var exclude string = os.Getenv("EXCLUDE")
var kmsARN string = os.Getenv("KMS_ARN")
var decryptedChannel string
var decryptedUserName string
var decryptedWebHookURL string

func HandleRequest(ctx context.Context, logsEvent events.CloudwatchLogsEvent) {
	var sb strings.Builder

	data, _ := logsEvent.AWSLogs.Parse()
	for _, logEvent := range data.LogEvents {
		fmt.Printf("Message = %s\n", logEvent.Message)
		sb.WriteString(logEvent.Message)
	}

	decryptedWebHookURL = string(awsmod.AwsKmsDecrypt(encryptedWebHookURL, kmsARN).Plaintext[:])
	decryptedUserName = string(awsmod.AwsKmsDecrypt(encryptedUserName, kmsARN).Plaintext[:])
	decryptedChannel = string(awsmod.AwsKmsDecrypt(encryptedChannel, kmsARN).Plaintext[:])

	sc := slack.SlackClient{
		WebHookUrl: decryptedWebHookURL,
		UserName:   decryptedUserName,
		Channel:    decryptedChannel,
	}

	//To send a notification with status (slack attachments)
	sr := slack.SlackJobNotification{
		Color:     "danger",
		IconEmoji: ":fire",
		Details:   sb.String(),
		Text:      "AWS Network Firewall Monitoring",
		Title:     data.LogGroup,
	}

	err := sc.SendJobNotification(sr)
	if err != nil {
		log.Fatal(err)
	}

}

func main() {
	lambda.Start(HandleRequest)
}
