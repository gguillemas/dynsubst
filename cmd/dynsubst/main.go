package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/kms"
)

var (
	table   string
	profile string
	inplace bool
	sess    *session.Session
)

const (
	stateEncrypted = "ENCRYPTED"
)

func init() {
	var err error
	flag.StringVar(&profile, "p", "default", "AWS profile to use")
	flag.BoolVar(&inplace, "i", false, "edit file in place")
	sess, err = session.NewSession()
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

	table = args[0]
	var file string
	if len(args) > 1 {
		file = args[1]
	}

	var text string
	if file == "" {
		input, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			log.Fatal(err)
		}
		text = string(input)
	} else {
		input, err := ioutil.ReadFile(file)
		if err != nil {
			log.Fatal(err)
		}
		text = string(input)
	}

	re := regexp.MustCompile(`{{(\w+:)?\w+}}`)
	output := re.ReplaceAllStringFunc(text, replaceFunc)

	if inplace {
		err := ioutil.WriteFile(file, []byte(output), 0)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		fmt.Println(output)
	}
}

func replaceFunc(input string) string {
	var err error

	re := regexp.MustCompile(`{{((?P<state>\w+):)?(?P<key>\w+)}}`)
	matches := re.FindStringSubmatch(input)

	var repl string
	encrypted := false
	for i, name := range re.SubexpNames() {
		if name == "state" {
			if matches[i] == stateEncrypted {
				encrypted = true
			}
		} else if name == "key" {
			repl, err = dynamoQuery(sess, table, matches[i])
			if err != nil {
				log.Println(err)
				return ""
			}
		}
	}

	if encrypted {
		repl, err = kmsDecrypt(repl)
		if err != nil {
			log.Println(err)
			return ""
		}
	}

	return repl
}

func dynamoQuery(sess *session.Session, table, field string) (string, error) {
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
		return "", fmt.Errorf("error querying for \"%v\": %v occurrences found", field, *resp.Count)
	}
	s := resp.Items[0]["Value"].S

	return *s, nil
}

func kmsDecrypt(b64 string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}

	decryptInput := &kms.DecryptInput{
		CiphertextBlob: decoded,
	}

	svc := kms.New(sess)
	res, err := svc.Decrypt(decryptInput)
	if err != nil {
		return "", err
	}

	return string(res.Plaintext), nil
}

func usage() {
	fmt.Println("Usage: dynsubst [flags] table [file]")
}
