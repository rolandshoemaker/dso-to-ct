package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/go-gorp/gorp"
)

const numChains int = 1000
const selectChains string = "SELECT chain_fp FROM chains WHERE valid = 1 ORDER BY chain_id ASC LIMIT ? OFFSET ?"

func getChains(db *gorp.DbMap, chainCh chan [][]byte, initialOffset int) error {
	offset := initialOffset
	for {
		var chains [][]byte
		_, err := db.Select(chains, selectChains, numChains, offset)
		if err == sql.ErrNoRows {
			break
		}
		if err != nil {
			return err
		}
		chainCh <- chains
		if len(chains) < numChains {
			break
		}
		offset += len(chains)
	}
	return nil
}

const selectReports string = "SELECT DISTINCT(cert_fp), end_entity FROM reports WHERE cert_fp = ?"
const selectRawCert string = "SELECT raw_cert FROM certs WHERE cert_fp = ?"

type report struct {
	certFP    string
	endEntity bool
}

func getCerts(db *gorp.DbMap, fingerprint []byte) ([][]byte, error) {
	var reports []report
	_, err := db.Select(reports, selectReports, fingerprint)
	if err != nil {
		return nil, err
	}
	var leaf []byte
	var others [][]byte
	for _, r := range reports {
		var raw []byte
		err := db.SelectOne(&raw, selectRawCert, r.certFP)
		if err != nil {
			return nil, err
		}
		if r.endEntity {
			leaf = raw
		} else {
			others = append(others, raw)
		}
	}
	if leaf == nil {
		return nil, errors.New("chain without end-entity")
	}
	return append([][]byte{leaf}, others...), nil
}

type httpClient interface {
	Post(string, string, io.Reader) (*http.Response, error)
}

type dryClient struct{}

func (dc *dryClient) Post(string, string, io.Reader) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK}, nil
}

const logAddr = "https://ct.googleapis.com/rocketeer/ct/v1/add-chain"

func submit(c httpClient, submission []byte) error {
	resp, err := c.Post(logAddr, "encoding/json", bytes.NewBuffer(submission))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var bodyStr string
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			bodyStr = err.Error()
		}
		bodyStr = string(body)
		return fmt.Errorf("non-200 status code, body: %s", bodyStr)
	}
	return nil
}

func submitChains(submissions chan []byte) error {
	c := new(http.Client)
	for submission := range submissions {
		err := submit(c, submission)
		if err != nil {
			return err
		}
	}
	return nil
}

type ctSubmission struct {
	Chain []string `json:"chain"`
}

func certsToSub(certs [][]byte) []byte {
	sub := ctSubmission{}
	for _, c := range certs {
		sub.Chain = append(sub.Chain, base64.StdEncoding.EncodeToString(c))
	}
	j, err := json.Marshal(sub)
	if err != nil {
		panic(err)
	}
	return j
}

func main() {
	chainsCh := make(chan [][]byte, 100)
	submissions := make(chan []byte, 100000)
	initialOffset := 0
	dbURI := ""

	innerDB, err := sql.Open("mysql", dbURI)
	if err != nil {
		panic(err)
	}
	db := &gorp.DbMap{Db: innerDB, Dialect: gorp.MySQLDialect{Engine: "InnoDB", Encoding: "UTF8"}}

	go func() {
		err := getChains(db, chainsCh, initialOffset)
		if err != nil {
			panic(err)
		}
	}()
	go func() {
		err := submitChains(submissions)
		if err != nil {
			panic(err)
		}
	}()
	for chains := range chainsCh {
		for _, chainFP := range chains {
			certs, err := getCerts(db, chainFP)
			if err != nil {
				panic(err)
			}
			submissions <- certsToSub(certs)
		}
	}
}
