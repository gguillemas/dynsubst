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
	table, profile, region string
	inplace, help          bool
	sess                   *session.Session
)

const (
	// Retrieve value as is.
	// This can be used in the case where a key coincidentally contains template syntax:
	// Ex.: "{{GET:DECRYPT:Password}}" would retrieve the value of the "DECRYPT:Password" key.
	// This is used as the default modifier when none is specified.
	modGet = "GET"
	// Decrypt value using AWS KMS.
	modDecrypt = "DECRYPT"
	// Remove SKIP modifier and do nothing else.
	// This can be used in the case where the same file will be processed more than once.
	// This option allows entries for different tables to be replaced in the same file.
	// It can be used along with any amount of modifiers such as: "{{SKIP:DECRYPT:Password}}".
	// Ex.: cat project.json | dynsubst project-settings | dynsubst project-credentials
	modSkip = "SKIP"

	helpMsg = `
Replace placeholders for their value in an AWS DynamoDB table.
Any key in between braces ("{{Key}}") is considered a placeholder.
Input can be supplied either from the standard input or from a file.

Placeholders accept the following modifiers:

  {{GET:Key}}
  Default. Will be replaced by the value of the "Key" key from AWS DynamoDB.
  Example: "{{Username}}" will be replaced by the value of the "Username" key.
  Example: "{{GET:Username}}" will be replaced by the value of the "Username" key.
  Example: "{{GET:DECRYPT:Username}}" will be replaced by the value of the "DECRYPT:Username" key.

  {{DECRYPT:Key}}
  Will be replaced by the value of the "Key" key from AWS DynamoDB decrypted with AWS KMS.
  Example: "{{DECRYPT:Password}}" will be replaced by the decrypted value of the "Password" key.

  {{SKIP:Key}}
  Will be replaced by the same placeholder after stripping the "SKIP" modifier.
  Example: "{{SKIP:DECRYPT:Password}}" will be replaced by "{{DECRYPT:Password}}".
`
)

func init() {
	var err error

	flag.Usage = func() {
		fmt.Println("Usage: dynsubst [flags] table [file]")
		flag.PrintDefaults()
		if help {
			fmt.Println(helpMsg)
		}
	}
	flag.StringVar(&profile, "p", "default", "specify AWS profile")
	flag.StringVar(&region, "r", "", "specify AWS region")
	flag.BoolVar(&inplace, "i", false, "edit file in place")
	flag.BoolVar(&help, "h", false, "show extended help")

	awsConfig := aws.NewConfig()
	if region != "" {
		awsConfig = awsConfig.WithRegion(region)
	}
	sess, err = session.NewSessionWithOptions(session.Options{
		Config:  *awsConfig,
		Profile: profile,
		// Force usage of shared AWS configuration.
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

	re := regexp.MustCompile(`{{(\w+?:)?.+?}}`)
	output := re.ReplaceAllStringFunc(text, replaceFunc)

	if inplace && file != "" {
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

	re := regexp.MustCompile(`{{((?P<mod>\w+?):)?(?P<key>.+?)}}`)
	matches := re.FindStringSubmatch(input)

	var repl, mod string
	for i, name := range re.SubexpNames() {
		switch name {
		case "mod":
			mod = matches[i]
		case "key":
			if mod == modSkip {
				repl = fmt.Sprintf("{{%s}}", matches[i])
				return ""
			} else {
				repl, err = dynamodbQuery(table, matches[i])
				if err != nil {
					log.Println(err)
					return ""
				}
			}
		}
	}

	if mod == modDecrypt {
		repl, err = kmsDecrypt(repl)
		if err != nil {
			log.Println(err)
			return ""
		}
	}

	return repl
}

// Returns the string value for the AWS DynamoDB attribute named "Value" for the key specified.
func dynamodbQuery(table, key string) (string, error) {
	svc := dynamodb.New(sess)

	queryInput := &dynamodb.QueryInput{
		TableName: aws.String(table),
		// TODO: Replace for KeyContidionExpression.
		KeyConditions: map[string]*dynamodb.Condition{
			"Key": {
				ComparisonOperator: aws.String("EQ"),
				AttributeValueList: []*dynamodb.AttributeValue{
					{
						S: &key,
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
		return "", fmt.Errorf("error querying for \"%v\": %v occurrences found", key, *resp.Count)
	}
	s := resp.Items[0]["Value"].S

	return *s, nil
}

func kmsDecrypt(value string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
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
