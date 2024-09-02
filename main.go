package main

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"

	arg "github.com/alexflint/go-arg"
	goahttp "goa.design/goa/v3/http"
)

const (
	loggerPrefix = "[serverapi]"
	cookieName   = "session_id"
	servicePort  = ":5678"
)

// Define command line flags, add any other flag required to configure the service.
type args struct {
	Local           bool   `arg:"--local,env:LOCAL" default:"false" help:"local mode"`
	LogLevel      string `arg:"--log-level,env:LOG_LEVEL" redact:"false" default:"info" help:"logging level" placeholder:"debug|info|warn|error"`
	Domain       string `arg:"--domain,env:DOMAIN" default:"" help:"Host domain name (overrides host domain specified in service design)"`
	Host         string `arg:"--host,env:HOST" default:"localhost" help:"Server host (valid values: localhost)"`
	HttpPort     string `arg:"--http-port,env:HTTP_PORT" default:"" help:"HTTP port (overrides host HTTP port specified in service design)"`
	Secure       bool   `arg:"--secure,env:SECURE" default:"false" help:"Use secure scheme"`
	DebugRequest bool   `arg:"--debug-request,env:DEBUG_REQUEST" default:"false" help:"Verbose request logging"`
}

func (args) Version() string {
	return fmt.Sprintf("Version: %v", build.Version)
}

func (args) Description() string {
	return "API service"
}

func (args) Epilogue() string {
	return "For more information check the README"
}

func main() {
	var args args
	arg.MustParse(&args)


	// init session manager
	sm := serverapi.NewSessionManager(cookieName, pool, args.Dev)
	sessionStore := serverapi.NewSessionStore(db, sm)

	// init session middleware
	applySessionMiddleware := func(server goahttp.Server) {
		server.Use(sm.LoadAndSave)
	}

	// init auth middleware
	applyAuthMiddleware := func(server goahttp.Server) {
		errResp := []byte(`{"Code":"` + serverapi.ExpiredCode.CodeStr() + `"}`)
		getUserSession := func(ctx context.Context) bool {
			return !sessionStore.GetVerified(ctx).Empty()
		}
		applySessionMiddleware(server)
	}

	// init config
	c := serv.Config{
	  ExternalURL:         "https://" + args.Domain,
		DevMode:             args.Dev,
		Domain:              args.Domain,
	}
	if c.Local {
		c.ExternalURL = "http://" + domain.Localhost + ":3000"
		c.Domain = domain.Localhost
	}

	serverPublicSvc := serverapi.NewServerPublic(sessionStore)
	devPublicSvc := serverapi.NewDevPublic()

	// Wrap the services in endpoints that can be invoked from other services
	// potentially running in different processes.
	var endpoints struct {
		Server           *server.Endpoints
		ServerMiddleware func(server goahttp.Server)
		DevPublic        *devpublic.Endpoints
	}
	{
		endpoints.Server = server.NewEndpoints(&serverSvc)
		endpoints.ServerMiddleware = applyAuthMiddleware
		endpoints.DevPublic = devpublic.NewEndpoints(devPublicSvc)
	}

	// Create channel used by both the signal handler and server goroutines
	// to notify the main goroutine when to stop the server.
	errc := make(chan error)

	// Setup interrupt handler. This optional step configures the process so
	// that SIGINT and SIGTERM signals cause the services to stop gracefully.
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errc <- fmt.Errorf("%s", <-c)
	}()

	// set background ctx
	ctx, cancel := context.WithCancel(context.Background())

	// Start the servers and send errors (if any) to the error channel.
	var waitShutdown sync.WaitGroup
	var u *url.URL
	switch args.Host {
	case domain.Localhost:
		{
			addr := "http://" + domain.Localhost + servicePort
			var err error
			u, err = url.Parse(addr)
			if err != nil {
				logger.Fatalf("%s invalid URL %#v: %s", loggerPrefix, addr, err)
			}
			if args.Secure {
				u.Scheme = domain.ProtocolHttps
			}
			if args.Domain != "" {
				u.Host = args.Domain
			}
			if args.HttpPort != "" {
				h, _, err := net.SplitHostPort(u.Host)
				if err != nil {
					logger.Fatalf("%s invalid URL %#v: %s", loggerPrefix, u.Host, err)
				}
				u.Host = net.JoinHostPort(h, args.HttpPort)
			} else if u.Port() == "" {
				u.Host = net.JoinHostPort(u.Host, "80")
			}
		}
	default:
		var err error
		u, err = url.Parse(args.Host)
		if err != nil {
			logger.Fatalf("%s invalid URL %#v: %s", loggerPrefix, args.Host, err)
		}
		// TODO: expose a k8s service
		u.Host = servicePort
	}
	handleHTTPServer(ctx, u, endpoints, &waitShutdown, errc, logger, args.DebugRequest)

	mainReportError(func() error {
		// Wait for signal.
		err := <-errc
		logger.Infof("%s exiting (%v)", loggerPrefix, err)

		// Send cancellation signal to the goroutines.
		cancel()

		waitShutdown.Wait()
		logger.Infof("%s exited", loggerPrefix)
		// SIGTERM is the normal k8s deployment
		if err.Error() == "terminated" {
			return nil
		}
		return err
	})
}

// MainReportError is only designed to be used in a top-level main function
// It will crash the program.
func mainReportError(mainError func() error) {
	if err := recovery.Call(mainError); err != nil {
		handleAndPanic(err)
	}
}

func handleAndPanic(err error) {
	slog.Error(fmt.Sprintf("%+v", err))
	// sentry.CaptureException(err)
	panic(fmt.Sprintf("%+v", err))
}

