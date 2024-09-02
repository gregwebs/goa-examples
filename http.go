package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	mdlwrsentrygoa "github.com/digitalmint/go-sentry-middleware/goa"
	sentryhttp "github.com/getsentry/sentry-go/http"
	chiware "github.com/go-chi/chi/v5/middleware"
	"github.com/gregwebs/errcode"
	goacode "github.com/gregwebs/errcode/goa"
	"github.com/gregwebs/errors"
	"github.com/gregwebs/go-recovery"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	goahttp "goa.design/goa/v3/http"
	httpware "goa.design/goa/v3/http/middleware"
	"goa.design/goa/v3/middleware"
)

type AllEndpoints struct {
    Server     *server.Endpoints
	Middleware func(server goahttp.Server)
	DevPublic  *devpublic.Endpoints
}

func useMiddleware(mux goahttp.Muxer, debugRequest bool, serversIn ...goahttp.Server) {
	sentryHandler := sentryhttp.New(sentryhttp.Options{
		Repanic: true,
	})

	servers := goahttp.Servers(serversIn)

	stackPrint := recovery.StackPrintStructured
	if debugRequest {
		stackPrint = recovery.StackPrintLines
		// This is too verbose for normal usage
		servers.Use(httpware.Debug(mux, os.Stdout))
	}
	// servers.Use(httpware.Log(adapter))
	servers.Use(httpware.RequestID())
	servers.Use(httpware.Trace())
	servers.Use(chiware.Logger)
	// Do we need compression or does our LB do that?
	// const defaultFlateLevel = -1
	// servers.Use(chiware.Compress(defaultFlateLevel))
	servers.Use(sentryHandler.Handle)
	eh := recovery.SlogHandler(recovery.SlogHandlerOpts{StackPrint: stackPrint})
	servers.Use(recovery.HTTPMiddleware(recovery.MiddlewareOpts{ErrorHandler: eh}))
	servers.Use(mdlwrsentrygoa.MiddlewareSentry500(mdlwrsentrygoa.Sentry500Options{}, logger))
}

func logLevel(err error) slog.Level {
	if errCode := errcode.CodeChain(err); errCode != nil {
		if errCode.Code().HTTPCode() >= 500 {
			return slog.LevelError
		}
	}
	return slog.LevelInfo
}

func customErrorResponse(ctx context.Context, errIn error) goahttp.Statuser {
	logArgs := []any{}
	// The user message ends up discarding system messages- ensure that is logged now
	if userMsg := errcode.GetUserMsg(errIn); userMsg != "" {
		slog.Log(ctx, logLevel(errIn), errIn.Error())
		logArgs = append(logArgs, "user", userMsg)
	}
	if record := errors.SlogRecord(errIn); record != nil {
		record.Add(logArgs...)
		if err := slog.Default().Handler().Handle(ctx, *record); err != nil {
			slog.ErrorContext(ctx, fmt.Sprintf("%+v", err))
		}
	}
	return goaJSONFormat{goacode.ErrorResponse(errIn)}
}

type goaJSONFormat struct{ goacode.ErrorCodeGoa }

func (goaFormat goaJSONFormat) MarshalJSON() ([]byte, error) {
	return json.Marshal(translateJSONFormat(errcode.NewJSONFormat(goaFormat.ErrorCodeGoa)))
}

type JSONFormat struct {
	Code      errcode.CodeStr      `json:"Code"`
	Msg       string               `json:"Message"`
	Data      interface{}          `json:"Data"`
	Operation string               `json:"Operation,omitempty"`
	Others    []errcode.JSONFormat `json:"Others,omitempty"`
}

func translateJSONFormat(jf errcode.JSONFormat) JSONFormat {
	return JSONFormat(jf)
}

// handleHTTPServer starts configures and starts a HTTP server on the given
// URL. It shuts down the server if any error is received in the error channel.
func handleHTTPServer(ctx context.Context, u *url.URL, endpoints AllEndpoints, waitShutdown *sync.WaitGroup, errc chan error, debugRequest bool) {
	// Provide the transport specific request decoder and response encoder.
	// The goa http package has built-in support for JSON, XML and gob.
	// Other encodings can be used by providing the corresponding functions,
	// see goa.design/implement/encoding.
	var (
		dec = goahttp.RequestDecoder
		enc = goahttp.ResponseEncoder
	)

	// Build the service HTTP request multiplexer and configure it to serve
	// HTTP requests to the service endpoints.
	var mux goahttp.Muxer
	{
		mux = goahttp.NewMuxer()
	}

	// Wrap the endpoints with the transport specific layers. The generated
	// server packages contains code generated from the design which maps
	// the service input and output data structures to HTTP requests and
	// responses.
	var (
		server       *svr.Server
		devPublicServer      *devpublicsvr.Server
	)
	{
		eh := errorHandler(logger)
		server = svr.New(endpoints.Server, mux, dec, enc, eh, customErrorResponse)
		endpoints.Middleware(server)
		devPublicServer = devpublicsvr.New(endpoints.DevPublic, mux, dec, enc, eh, customErrorResponse, nil, nil, nil, nil)
		useMiddleware(logger, mux, debugRequest, server, devPublicServer)
	}

	// Configure the mux.
	svr.Mount(mux, server)
	devpublicsvr.Mount(mux, devPublicServer)

	// Wrap the multiplexer with additional middlewares. Middlewares mounted
	// here apply to all the service endpoints.
	var handler http.Handler = otelhttp.NewHandler(mux, "/")

	// Start HTTP server using default configuration, change the code to
	// configure the server as required by your service.
	srv := &http.Server{Addr: u.Host, Handler: handler, ReadHeaderTimeout: time.Second * 60}
	for _, m := range server.Mounts {
		logger.Infof("%s HTTP %q mounted on %s %s", loggerPrefix, m.Method, m.Verb, m.Pattern)
	}
	for _, m := range devPublicServer.Mounts {
		logger.Infof("%s HTTP %q mounted on %s %s", loggerPrefix, m.Method, m.Verb, m.Pattern)
	}

	(*waitShutdown).Add(1)
	go func() {
		defer (*waitShutdown).Done()

		// Start HTTP server in a separate goroutine.
		go recovery.Go(func() error {
			errc <- recovery.Call(func() error {
				logger.Infof("%s HTTP server listening on %q", loggerPrefix, u.Host)
				return srv.ListenAndServe()
			})
			return nil
		})

		<-ctx.Done()
		logger.Infof("%s shutting down HTTP server at %q", loggerPrefix, u.Host)

		// Shutdown gracefully with a 30s timeout.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		err := recovery.Call(func() error {
			return srv.Shutdown(ctx)
		})
		if err != nil {
			logger.Errorf("%s failed to shutdown: %v", loggerPrefix, err)
		}
	}()
}

// errorHandler returns a function that writes and logs the given error.
// The function also writes and logs the error unique ID so that it's possible
// to correlate.
func errorHandler() func(context.Context, http.ResponseWriter, error) {
	return func(ctx context.Context, w http.ResponseWriter, err error) {
		id := ctx.Value(middleware.RequestIDKey).(string)
		_, _ = w.Write([]byte("[" + id + "] encoding: " + err.Error()))
		logger.Errorf("%s [%s] ERROR: %s", loggerPrefix, id, err.Error())
	}
}
