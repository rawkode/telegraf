package elastic_apm

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/influxdata/telegraf"
	tlsint "github.com/influxdata/telegraf/internal/tls"
	"github.com/influxdata/telegraf/plugins/inputs"
	"github.com/influxdata/telegraf/plugins/parsers"
)

// defaultMaxBodySize is the default maximum request body size, in bytes.
// if the request body is over this size, we will return an HTTP 413 error.
// 500 MB
const defaultMaxBodySize = 500 * 1024 * 1024

const (
	body  = "body"
	query = "query"
)

// TimeFunc provides a timestamp for the metrics
type TimeFunc func() time.Time

// ElasticApm is an input plugin that acts as an elastic-apm server
type ElasticApm struct {
	ServiceAddress string `toml:"service_address"`
	Port           int    `toml:"port"`
	tlsint.ServerConfig

	TimeFunc
	Log telegraf.Logger

	wg sync.WaitGroup

	listener net.Listener

	parsers.Parser
	acc telegraf.Accumulator
}

const sampleConfig = `
  ## Address and port to host HTTP listener on
  service_address = ":8080"

  ## Set one or more allowed client CA certificate file names to
  ## enable mutually authenticated TLS connections
  # tls_allowed_cacerts = ["/etc/telegraf/clientca.pem"]

  ## Add service certificate and key
  # tls_cert = "/etc/telegraf/cert.pem"
  # tls_key = "/etc/telegraf/key.pem"

  ## Data format to consume.
  ## Each data format has its own unique set of configuration options, read
  ## more about them here:
  ## https://github.com/influxdata/telegraf/blob/master/docs/DATA_FORMATS_INPUT.md
  data_format = "influx"
`

func (e *ElasticApm) SampleConfig() string {
	return sampleConfig
}

func (e *ElasticApm) Description() string {
	return "Elastic APM Server"
}

func (e *ElasticApm) Gather(_ telegraf.Accumulator) error {
	return nil
}

func (e *ElasticApm) SetParser(parser parsers.Parser) {
	e.Parser = parser
}

// Start starts the Elastic APM Server service.
func (e *ElasticApm) Start(acc telegraf.Accumulator) error {
	e.acc = acc

	tlsConf, err := e.ServerConfig.TLSConfig()
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:      e.ServiceAddress,
		Handler:   e,
		TLSConfig: tlsConf,
	}

	var listener net.Listener
	if tlsConf != nil {
		listener, err = tls.Listen("tcp", e.ServiceAddress, tlsConf)
	} else {
		listener, err = net.Listen("tcp", e.ServiceAddress)
	}
	if err != nil {
		return err
	}
	e.listener = listener
	e.Port = listener.Addr().(*net.TCPAddr).Port

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		server.Serve(e.listener)
	}()

	e.Log.Infof("Listening on %s", listener.Addr().String())

	return nil
}

// Stop cleans up all resources
func (e *ElasticApm) Stop() {
	e.listener.Close()
	e.wg.Wait()
}

func (e *ElasticApm) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	// We only accept HTTP/2!
	// (Normally it's quite common to accept HTTP/1.- and HTTP/2 together.)
	if req.ProtoMajor != 2 {
		e.Log.Debugf("Not a HTTP/2 request, rejected!, %v", req.Proto)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	e.serveWrite(res, req)
}

func (e *ElasticApm) serveWrite(res http.ResponseWriter, req *http.Request) {
	e.Log.Debug("Closing 204")
	res.WriteHeader(http.StatusNoContent)
}

// func (e *HTTPListenerV2) collectBody(res http.ResponseWriter, req *http.Request) ([]byte, bool) {
// 	body := req.Body

// 	// Handle gzip request bodies
// 	if req.Header.Get("Content-Encoding") == "gzip" {
// 		var err error
// 		body, err = gzip.NewReader(req.Body)
// 		if err != nil {
// 			e.Log.Debug(err.Error())
// 			badRequest(res)
// 			return nil, false
// 		}
// 		defer body.Close()
// 	}

// 	body = http.MaxBytesReader(res, body, e.MaxBodySize.Size)
// 	bytes, err := ioutil.ReadAll(body)
// 	if err != nil {
// 		tooLarge(res)
// 		return nil, false
// 	}

// 	return bytes, true
// }

// func (e *HTTPListenerV2) collectQuery(res http.ResponseWriter, req *http.Request) ([]byte, bool) {
// 	rawQuery := req.URL.RawQuery

// 	query, err := url.QueryUnescape(rawQuery)
// 	if err != nil {
// 		e.Log.Debugf("Error parsing query: %s", err.Error())
// 		badRequest(res)
// 		return nil, false
// 	}

// 	return []byte(query), true
// }

// func tooLarge(res http.ResponseWriter) {
// 	res.Header().Set("Content-Type", "application/json")
// 	res.WriteHeader(http.StatusRequestEntityTooLarge)
// 	res.Write([]byte(`{"error":"http: request body too large"}`))
// }

// func methodNotAllowed(res http.ResponseWriter) {
// 	res.Header().Set("Content-Type", "application/json")
// 	res.WriteHeader(http.StatusMethodNotAllowed)
// 	res.Write([]byte(`{"error":"http: method not allowed"}`))
// }

// func internalServerError(res http.ResponseWriter) {
// 	res.Header().Set("Content-Type", "application/json")
// 	res.WriteHeader(http.StatusInternalServerError)
// }

// func badRequest(res http.ResponseWriter) {
// 	res.Header().Set("Content-Type", "application/json")
// 	res.WriteHeader(http.StatusBadRequest)
// 	res.Write([]byte(`{"error":"http: bad request"}`))
// }

// func (e *HTTPListenerV2) authenticateIfSet(handler http.HandlerFunc, res http.ResponseWriter, req *http.Request) {
// 	if e.BasicUsername != "" && e.BasicPassword != "" {
// 		reqUsername, reqPassword, ok := req.BasicAuth()
// 		if !ok ||
// 			subtle.ConstantTimeCompare([]byte(reqUsername), []byte(e.BasicUsername)) != 1 ||
// 			subtle.ConstantTimeCompare([]byte(reqPassword), []byte(e.BasicPassword)) != 1 {

// 			http.Error(res, "Unauthorized.", http.StatusUnauthorized)
// 			return
// 		}
// 		handler(res, req)
// 	} else {
// 		handler(res, req)
// 	}
// }

func init() {
	inputs.Add("elastic_apm", func() telegraf.Input {
		return &ElasticApm{
			ServiceAddress: ":8080",
			TimeFunc:       time.Now,
		}
	})
}
