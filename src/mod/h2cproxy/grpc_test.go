package h2cproxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	grpcpb "google.golang.org/grpc/interop/grpc_testing"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type duplexServer struct {
	grpcpb.UnimplementedTestServiceServer
}

func (duplexServer) FullDuplexCall(stream grpc.BidiStreamingServer[grpcpb.StreamingOutputCallRequest, grpcpb.StreamingOutputCallResponse]) error {
	// Send headers before reading a message to detect request-body read-ahead.
	if err := stream.SendHeader(metadata.Pairs("server-ready", "true")); err != nil {
		return err
	}
	stream.SetTrailer(metadata.Pairs("finished", "true"))
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := stream.Send(&grpcpb.StreamingOutputCallResponse{Payload: req.Payload}); err != nil {
			return err
		}
	}
}

func TestGRPCUnaryStreamingTrailersAndCancellation(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	watchStopped := make(chan struct{}, 1)
	authenticate := func(ctx context.Context) error {
		md, _ := metadata.FromIncomingContext(ctx)
		if values := md.Get("x-api-key"); len(values) != 1 || values[0] != "test-key" {
			return status.Error(codes.Unauthenticated, "API key required")
		}
		return nil
	}
	backend := grpc.NewServer(
		grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			if err := authenticate(ctx); err != nil {
				return nil, err
			}
			return handler(ctx, req)
		}),
		grpc.StreamInterceptor(func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			if err := authenticate(stream.Context()); err != nil {
				return err
			}
			err := handler(srv, stream)
			if strings.HasSuffix(info.FullMethod, "/Watch") {
				watchStopped <- struct{}{}
			}
			return err
		}),
	)
	healthServer := health.NewServer()
	healthServer.SetServingStatus("project", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(backend, healthServer)
	grpcpb.RegisterTestServiceServer(backend, duplexServer{})
	go backend.Serve(lis)
	t.Cleanup(backend.Stop)
	m := testManager(t)
	saveTestRule(t, m, "grpc.example.com", lis.Addr().String())
	frontend := httptest.NewUnstartedServer(m)
	frontend.EnableHTTP2 = true
	frontend.StartTLS()
	t.Cleanup(frontend.Close)
	conn, err := grpc.NewClient(strings.TrimPrefix(frontend.URL, "https://"),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})),
		grpc.WithAuthority("grpc.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := healthpb.NewHealthClient(conn)
	if _, err := client.Check(ctx, &healthpb.HealthCheckRequest{Service: "project"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated status = %v", err)
	}
	authCtx := metadata.AppendToOutgoingContext(ctx, "x-api-key", "test-key")
	res, err := client.Check(authCtx, &healthpb.HealthCheckRequest{Service: "project"})
	if err != nil || res.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("unary response: %v %v", res, err)
	}
	if _, err := client.Check(authCtx, &healthpb.HealthCheckRequest{Service: "missing"}); status.Code(err) != codes.NotFound {
		t.Fatalf("error trailers lost: %v", err)
	}
	watchCtx, cancelWatch := context.WithCancel(authCtx)
	defer cancelWatch()
	watch, err := client.Watch(watchCtx, &healthpb.HealthCheckRequest{Service: "project"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := watch.Recv()
	if err != nil || first.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("first stream response: %v %v", first, err)
	}
	healthServer.SetServingStatus("project", healthpb.HealthCheckResponse_NOT_SERVING)
	second, err := watch.Recv()
	if err != nil || second.GetStatus() != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("second stream response: %v %v", second, err)
	}
	cancelWatch()
	select {
	case <-watchStopped:
	case <-ctx.Done():
		t.Fatal("client cancellation did not reach backend")
	}

	duplex, err := grpcpb.NewTestServiceClient(conn).FullDuplexCall(authCtx)
	if err != nil {
		t.Fatal(err)
	}
	headers, err := duplex.Header()
	if err != nil || len(headers.Get("server-ready")) != 1 {
		t.Fatalf("headers blocked before first message: %v %v", headers, err)
	}
	for _, body := range []string{"first", "second", "third"} {
		if err := duplex.Send(&grpcpb.StreamingOutputCallRequest{Payload: &grpcpb.Payload{Body: []byte(body)}}); err != nil {
			t.Fatal(err)
		}
		reply, err := duplex.Recv()
		if err != nil || string(reply.GetPayload().GetBody()) != body {
			t.Fatalf("duplex reply: %v %v", reply, err)
		}
	}
	if err := duplex.CloseSend(); err != nil {
		t.Fatal(err)
	}
	if _, err := duplex.Recv(); err != io.EOF {
		t.Fatalf("duplex completion = %v", err)
	}
	if values := duplex.Trailer().Get("finished"); len(values) != 1 || values[0] != "true" {
		t.Fatalf("unannounced trailers lost: %v", duplex.Trailer())
	}
}
