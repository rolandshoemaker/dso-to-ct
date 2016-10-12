package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gorp/gorp"
	_ "github.com/go-sql-driver/mysql"
)

const (
	maxChains     int    = 1000
	selectChains  string = "SELECT chain_fp, chain_id FROM chains WHERE valid = 1 ORDER BY chain_id ASC LIMIT ? OFFSET ?"
	selectReports string = "SELECT DISTINCT(cert_fp), is_end_entity FROM reports WHERE chain_fp = ?"
	selectRawCert string = "SELECT raw_cert FROM certs WHERE cert_fp = ?"
	logAddr              = "https://ct.googleapis.com/rocketeer/ct/v1/add-chain"
)

var (
	lastSubmittedChain int64
	numSubmitted       int64
	numNewSubmitted    int64

	dbURI      = flag.String("dbURI", "", "")
	dryRun     = flag.Bool("dryRun", false, "")
	initOffset = flag.Int("initialChainID", 0, "")
	workers    = flag.Int("workers", 5, "")
	statPeriod = flag.Duration("statsInterval", time.Second*15, "")
)

type chain struct {
	Fingerprint []byte   `db:"chain_fp"`
	ID          int64    `db:"chain_id"`
	certs       [][]byte `db:"-"`
}

func getChains(db *gorp.DbMap, chainCh chan []chain) error {
	offset := *initOffset
	for {
		var chains []chain
		_, err := db.Select(&chains, selectChains, maxChains, offset)
		if err == sql.ErrNoRows {
			break
		}
		if err != nil {
			return err
		}
		chainCh <- chains
		if len(chains) < maxChains {
			break
		}
		offset += len(chains)
	}
	return nil
}

type report struct {
	CertFP    string `db:"cert_fp"`
	EndEntity bool   `db:"is_end_entity"`
}

func getCerts(db *gorp.DbMap, partialChain *chain) error {
	var reports []report
	_, err := db.Select(&reports, selectReports, partialChain.Fingerprint)
	if err != nil {
		return err
	}
	var leaf []byte
	var others [][]byte
	for _, r := range reports {
		var raw []byte
		err := db.SelectOne(&raw, selectRawCert, r.CertFP)
		if err != nil {
			return err
		}
		if r.EndEntity {
			leaf = raw
		} else {
			others = append(others, raw)
		}
	}
	if leaf == nil {
		return errors.New("chain without end-entity")
	}
	partialChain.certs = append([][]byte{leaf}, others...)
	return nil
}

type httpClient interface {
	Post(string, string, io.Reader) (*http.Response, error)
}

type dryClient struct{}

func (dc *dryClient) Post(string, string, io.Reader) (*http.Response, error) {
	time.Sleep(500 * time.Millisecond)
	return &http.Response{StatusCode: http.StatusOK}, nil
}

type ctResponse struct {
	Timestamp int64
}

func submit(c httpClient, submission chain) error {
	resp, err := c.Post(logAddr, "encoding/json", bytes.NewBuffer(certsToSub(submission.certs)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var bodyStr string
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			bodyStr = err.Error()
		}
		bodyStr = string(body)
		return fmt.Errorf("non-200 status code, body: %s", bodyStr)
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var ctr ctResponse
	err = json.Unmarshal(b, &ctr)
	if err != nil {
		return err
	}
	if ctr.Timestamp > int64(time.Now().UTC().Add(-time.Hour).UnixNano()/1000) {
		atomic.AddInt64(&numNewSubmitted, 1)
	}
	atomic.StoreInt64(&lastSubmittedChain, submission.ID)
	atomic.AddInt64(&numSubmitted, 1)
	return nil
}

func submitChains(submissions chan chain) error {
	var c httpClient
	if *dryRun {
		c = &dryClient{}
	} else {
		c = new(http.Client)
	}
	wg := new(sync.WaitGroup)
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			for submission := range submissions {
				err := submit(c, submission)
				if err != nil {
					continue
				}
				atomic.StoreInt64(&lastSubmittedChain, submission.ID)
			}
			wg.Done()
		}()
	}
	wg.Wait()
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

func printStats(t *time.Ticker, chains chan []chain, submissions chan chain) {
	lastNumSubmitted := int64(0)
	rate := 0.0
	for range t.C {
		num := atomic.LoadInt64(&numSubmitted)
		rate = float64(num-lastNumSubmitted) / 30.0
		fmt.Printf(
			"%s [pending chains: %d, pending submissions: %d, completed submissions: %d (%d new), submission rate: %3.2f/s, last submitted chain id: %d]\n",
			time.Now().Format(time.RFC1123),
			len(chains)*maxChains,
			len(submissions),
			num,
			atomic.LoadInt64(&numNewSubmitted),
			rate,
			atomic.LoadInt64(&lastSubmittedChain),
		)
		lastNumSubmitted = num
	}
}

func main() {
	flag.Parse()
	chainsCh := make(chan []chain, 100)
	submissions := make(chan chain, 100000)

	innerDB, err := sql.Open("mysql", *dbURI)
	if err != nil {
		panic(err)
	}
	db := &gorp.DbMap{Db: innerDB, Dialect: gorp.MySQLDialect{Engine: "InnoDB", Encoding: "UTF8"}}

	defer func() {
		// record last submitted chain id
		var recovered interface{}
		if r := recover(); r != nil {
			recovered = r
		}
		fmt.Printf("\n# [Last submitted chain ID: %d]\n", atomic.LoadInt64(&lastSubmittedChain))
		if recovered != nil {
			fmt.Println("ERROR", recovered)
			os.Exit(1)
		}
	}()

	t := time.NewTicker(*statPeriod)
	go printStats(t, chainsCh, submissions)

	go func() {
		err := getChains(db, chainsCh)
		if err != nil {
			panic(err)
		}
		close(chainsCh)
	}()

	finished := make(chan struct{}, 1)
	go func() {
		err := submitChains(submissions)
		if err != nil {
			panic(err)
		}
		finished <- struct{}{}
	}()

	for chains := range chainsCh {
		for _, partialChain := range chains {
			err := getCerts(db, &partialChain)
			if err != nil {
				// panic(err)
				continue // skip broken chains
			}
			submissions <- partialChain
		}
	}
	close(submissions)
	<-finished
}
