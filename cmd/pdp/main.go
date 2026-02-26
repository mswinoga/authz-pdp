package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/marcin/authz-pdp/internal/logsetup"
	"github.com/marcin/authz-pdp/pdp/cel"
	actorpkg "github.com/marcin/authz-pdp/pdp/model/actor"
	operationpkg "github.com/marcin/authz-pdp/pdp/model/operation"
	subjectpkg "github.com/marcin/authz-pdp/pdp/model/subject"
	"github.com/marcin/authz-pdp/pdp/policy"
)

var (
	policyFile     = flag.String("policy-file", "", "path to policy YAML (required)")
	jwtMetadataKey = flag.String("jwt-metadata-key", "", "jwt_authn payload_in_metadata key (required)")
	port           = flag.Int("port", 9191, "gRPC listen port")
	logLevelFlag   = flag.String("log-level", "info", "log levels: default[,logger:level,...] e.g. info,cel:debug")
)

type server struct {
	envoy_auth.UnimplementedAuthorizationServer
	evaluator      *cel.Evaluator
	jwtMetadataKey string
	logger         *slog.Logger
}

func main() {
	flag.Parse()

	if *policyFile == "" {
		log.Fatal("-policy-file is required")
	}
	if *jwtMetadataKey == "" {
		log.Fatal("-jwt-metadata-key is required")
	}

	logCfg, err := logsetup.Parse(*logLevelFlag)
	if err != nil {
		log.Fatalf("invalid -log-level: %v", err)
	}
	base := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})
	loggers := map[string]*slog.Logger{
		"server": logsetup.Build("server", logCfg, base),
		"cel":    logsetup.Build("cel", logCfg, base),
		"policy": logsetup.Build("policy", logCfg, base),
		"input":  logsetup.Build("input", logCfg, base),
	}
	slog.SetDefault(loggers["server"])

	actorpkg.SetLogger(loggers["input"])
	subjectpkg.SetLogger(loggers["input"])
	operationpkg.SetLogger(loggers["input"])

	p, err := policy.LoadFile(*policyFile, loggers["policy"])
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}

	ev, err := cel.NewEvaluator(p, loggers["cel"])
	if err != nil {
		log.Fatalf("compile policy: %v", err)
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	envoy_auth.RegisterAuthorizationServer(grpcServer, &server{
		evaluator:      ev,
		jwtMetadataKey: *jwtMetadataKey,
		logger:         loggers["server"],
	})

	loggers["server"].Info("listening",
		"addr", lis.Addr().String(),
		"policy", *policyFile,
		"jwt-metadata-key", *jwtMetadataKey,
	)

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)
		<-c
		loggers["server"].Info("shutting down")
		grpcServer.GracefulStop()
	}()

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

func (s *server) Check(
	ctx context.Context,
	req *envoy_auth.CheckRequest,
) (*envoy_auth.CheckResponse, error) {
	resource := req.GetAttributes().GetRequest().GetHttp().GetPath()
	action := req.GetAttributes().GetRequest().GetHttp().GetMethod()

	actor := actorpkg.Parse(req.GetAttributes().GetSource().GetCertificate())
	subject := subjectpkg.Extract(req, s.jwtMetadataKey)
	operation := operationpkg.Extract(req)

	allow, ruleID := s.evaluator.Evaluate(cel.EvalContext{
		Actor:     actor,
		Subject:   subject,
		Operation: operation,
		Resource:  resource,
		Action:    action,
	})

	actorCN := ""
	if actor != nil {
		actorCN = actor.Cn
	}
	s.logger.Info("decision",
		"actor_cn", actorCN,
		"resource", resource,
		"action", action,
		"rule", ruleID,
		"allow", allow,
	)

	if allow {
		return okResponse(), nil
	}
	return deniedResponse(), nil
}

func okResponse() *envoy_auth.CheckResponse {
	return &envoy_auth.CheckResponse{
		Status: &status.Status{Code: int32(codes.OK)},
		HttpResponse: &envoy_auth.CheckResponse_OkResponse{
			OkResponse: &envoy_auth.OkHttpResponse{},
		},
	}
}

func deniedResponse() *envoy_auth.CheckResponse {
	return &envoy_auth.CheckResponse{
		Status: &status.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &envoy_auth.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_auth.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
			},
		},
	}
}
