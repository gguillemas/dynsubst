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
	region  string
	inplace bool
	sess    *session.Session
)

const (
	stateEncrypted = "ENCRYPTED"
	stateBase64    = "BASE64"
	statePlain     = "PLAIN"
)

func init() {
	var err error
	flag.Usage = func() {
		fmt.Println("Usage: dynsubst [flags] table [file]")
		flag.PrintDefaults()
	}
	flag.StringVar(&profile, "p", "default", "AWS profile to use")
	flag.StringVar(&region, "r", "", "AWS region to use")
	flag.BoolVar(&inplace, "i", false, "edit file in place")
	awsConfig := aws.NewConfig()
	if region != "" {
		awsConfig = awsConfig.WithRegion(region)
	}
	sess, err = session.NewSessionWithOptions(session.Options{
		Config:            *awsConfig,
		Profile:           profile,
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
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

	var repl, state string
	for i, name := range re.SubexpNames() {
		if name == "state" {
			state = matches[i]
		} else if name == "key" {
			repl, err = dynamodbQuery(sess, table, matches[i])
			if err != nil {
				log.Println(err)
				return ""
			}
		}
	}

	switch state {
	case stateEncrypted:
		repl, err = kmsDecrypt(repl)
		if err != nil {
			log.Println(err)
			return ""
		}
	case stateBase64:
		dec, err := base64.StdEncoding.DecodeString(repl)
		if err != nil {
			log.Println(err)
			return ""
		}
		repl = string(dec)
	case statePlain:
		fallthrough
	default:
		break
	}

	return repl
}

func dynamodbQuery(sess *session.Session, table, field string) (string, error) {
	svc := dynamodb.New(sess)

	queryInput := &dynamodb.QueryInput{
		TableName: aws.String(table),
		// TODO: Replace for KeyContidionExpression.
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
