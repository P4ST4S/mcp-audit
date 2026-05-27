package otel

import "strconv"

type tracesPayload struct {
	ResourceSpans []resourceSpans `json:"resourceSpans"`
}

type resourceSpans struct {
	Resource   resource     `json:"resource"`
	ScopeSpans []scopeSpans `json:"scopeSpans"`
}

type resource struct {
	Attributes []keyValue `json:"attributes,omitempty"`
}

type scopeSpans struct {
	Scope instrumentationScope `json:"scope"`
	Spans []otlpSpan           `json:"spans"`
}

type instrumentationScope struct {
	Name string `json:"name"`
}

type otlpSpan struct {
	TraceID           string     `json:"traceId"`
	SpanID            string     `json:"spanId"`
	Name              string     `json:"name"`
	Kind              int        `json:"kind"`
	StartTimeUnixNano string     `json:"startTimeUnixNano"`
	EndTimeUnixNano   string     `json:"endTimeUnixNano"`
	Attributes        []keyValue `json:"attributes,omitempty"`
	Status            otlpStatus `json:"status,omitempty"`
}

type otlpStatus struct {
	Message string `json:"message,omitempty"`
	Code    int    `json:"code,omitempty"`
}

type keyValue struct {
	Key   string   `json:"key"`
	Value anyValue `json:"value"`
}

type anyValue struct {
	StringValue string `json:"stringValue,omitempty"`
	IntValue    string `json:"intValue,omitempty"`
	BoolValue   *bool  `json:"boolValue,omitempty"`
}

func stringAttr(key, value string) keyValue {
	return keyValue{Key: key, Value: anyValue{StringValue: value}}
}

func intAttr(key string, value int64) keyValue {
	return keyValue{Key: key, Value: anyValue{IntValue: strconv.FormatInt(value, 10)}}
}

func boolAttr(key string, value bool) keyValue {
	return keyValue{Key: key, Value: anyValue{BoolValue: &value}}
}
