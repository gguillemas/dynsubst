package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
)

var (
	profile string
	sess    *session.Session
)

const (
	stateEncrypted = "ENCRYPTED"
)

func init() {
	flag.StringVar(&profile, "p", "default", "AWS profile to use")
	sess, err := session.NewSession()
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		usage()
		os.Exit(1)
	}

	input, err := ioutil.ReadAll(os.Stdin)
	text := string(input)

	re := regexp.MustCompile(`{{((<state>\w+):)?(?<key>\w+)}}`)
	output := re.ReplaceAllStringFunc(text, replaceFunc)

	fmt.Println(output)
}

func replaceFunc(input string) string {
	re := regexp.MustCompile(`{{((<state>\w+):)?(?<key>\w+)}}`)
	matches := re.FindStringSubmatch(input)

	var repl string
	var encrypted bool
	for i, name := range re.SubexpNames() {
		if name == "state" {
			if matches[i] == stateEncrypted {
				encrypted = true
			}
		} else if name == "key" {
			repl, err := dynamoQuery(table, matches[i])
			if err != nil {
				log.Println(err)
				return ""
			}
		}
	}

	return repl
}

func dynamoQuery(table, field string) (string, error) {
	svc := dynamodb.New(sess)

	queryInput := &dynamodb.QueryInput{
		TableName: aws.String(table),
		KeyConditions: map[string]*dynamodb.Condition{
			"Key": {
				ComparisonOperator: aws.String("EQ"),
				AttributeValueList: []*dynamodb.AttributeValue{
					{
						S: &field,
					},
				},
			},
		},
	}

	resp, err := svc.Query(queryInput)
	if err != nil {
		return "", err
	}

	if *resp.Count != 1 {
		return "", fmt.Errorf("error querying for %v: %v occurrences found", field, *resp.Count)
	}
	s := resp.Items[0]["Value"].S

	return *s, nil
}

func usage() {
	fmt.Println("Usage: dynsubst [-p profile] table")
}
