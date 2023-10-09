package otel

import (
	"context"
	"log"
	"os"

	"github.com/juicebox-systems/juicebox-software-realm/types"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

var tracerName = "jb-sw-realm"

func StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return otel.Tracer(tracerName).Start(ctx, name, opts...)
}

func RecordOutcome(err error, span trace.Span) error {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	} else {
		span.SetStatus(codes.Ok, "")
	}
	return err
}

func IncrementInt64Counter(ctx context.Context, name string, attributes ...attribute.KeyValue) error {
	counter, err := otel.Meter(tracerName).Int64Counter(name)
	if err != nil {
		return err
	}
	counter.Add(ctx, 1, metric.WithAttributes(attributes...))
	return nil
}

func initResource(realmID types.RealmID) *resource.Resource {
	resource, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(tracerName),
			attribute.String("realm", realmID.String()),
		),
	)
	if err != nil {
		log.Fatalf("error initializing resource: %+v", err)
	}
	return resource
}

func InitTraceProvider(ctx context.Context, serviceName string, realmID types.RealmID) *sdktrace.TracerProvider {
	tracerName = serviceName

	resource := initResource(realmID)
	opts := []sdktrace.TracerProviderOption{
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithResource(resource),
	}

	endpoint := os.Getenv("OPENTELEMETRY_ENDPOINT")
	if endpoint != "" {
		exporter, err := otlptrace.New(ctx, otlptracegrpc.NewClient(
			otlptracegrpc.WithEndpoint(endpoint),
			otlptracegrpc.WithInsecure(),
		))
		if err != nil {
			log.Fatalf("creating OTLP trace exporter: %v", err)
		}
		opts = append(opts, sdktrace.WithBatcher(exporter))
	}

	tp := sdktrace.NewTracerProvider(opts...)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	return tp
}

func InitMeterProvider(ctx context.Context, realmID types.RealmID) *sdkmetric.MeterProvider {
	resource := initResource(realmID)

	opts := []sdkmetric.Option{
		sdkmetric.WithResource(resource),
	}

	endpoint := os.Getenv("OPENTELEMETRY_ENDPOINT")
	if endpoint != "" {
		exporter, err := otlpmetricgrpc.New(
			ctx,
			otlpmetricgrpc.WithEndpoint(endpoint),
			otlpmetricgrpc.WithInsecure(),
		)
		if err != nil {
			log.Fatalf("creating OTLP metric exporter: %v", err)
		}
		opts = append(opts, sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter)))
	}

	mp := sdkmetric.NewMeterProvider(opts...)
	otel.SetMeterProvider(mp)
	return mp
}
