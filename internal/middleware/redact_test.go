package middleware

import (
	"encoding/json"
	"reflect"
	"testing"
)

// assertJSONSemanticEqual checks if two JSON payloads are semantically equivalent.
// If either is invalid JSON, it falls back to a literal string/byte comparison.
func assertJSONSemanticEqual(t *testing.T, actualRaw, expectedRaw []byte) {
	t.Helper()
	if string(actualRaw) == string(expectedRaw) {
		return
	}
	var actualObj, expectedObj any
	errActual := json.Unmarshal(actualRaw, &actualObj)
	errExpected := json.Unmarshal(expectedRaw, &expectedObj)
	if errActual != nil || errExpected != nil {
		if string(actualRaw) != string(expectedRaw) {
			t.Errorf("mismatch:\nactual:   %q\nexpected: %q", string(actualRaw), string(expectedRaw))
		}
		return
	}
	if !reflect.DeepEqual(actualObj, expectedObj) {
		t.Errorf("JSON mismatch:\nactual:   %s\nexpected: %s", string(actualRaw), string(expectedRaw))
	}
}

func TestRedactor_NilReceiver(t *testing.T) {
	var r *Redactor
	input := []byte(`{"password":"123"}`)
	output := r.Redact(input)
	assertJSONSemanticEqual(t, output, input)
}

func TestRedactor_Disabled(t *testing.T) {
	r := NewRedactor(false, nil)
	input := []byte(`{"password":"123"}`)
	output := r.Redact(input)
	assertJSONSemanticEqual(t, output, input)
}

func TestRedactor_InvalidJSON(t *testing.T) {
	r := NewRedactor(true, nil)
	input := []byte(`{"password":`)
	output := r.Redact(input)
	assertJSONSemanticEqual(t, output, input)
}

func TestRedactor_DefaultPatterns_Root(t *testing.T) {
	r := NewRedactor(true, nil)
	input := []byte(`{
		"password": "p1",
		"token": "t1",
		"secret": "s1",
		"api_key": "k1",
		"bearer": "b1",
		"authorization": "a1",
		"normal": "n1"
	}`)
	expected := []byte(`{
		"password": "[REDACTED]",
		"token": "[REDACTED]",
		"secret": "[REDACTED]",
		"api_key": "[REDACTED]",
		"bearer": "[REDACTED]",
		"authorization": "[REDACTED]",
		"normal": "n1"
	}`)
	output := r.Redact(input)
	assertJSONSemanticEqual(t, output, expected)
}

func TestRedactor_DefaultPatterns_Nested(t *testing.T) {
	r := NewRedactor(true, nil)
	input := []byte(`{
		"nested": {
			"inner_secret": "my_secret",
			"info": {
				"bearer_token": "token123"
			}
		}
	}`)
	expected := []byte(`{
		"nested": {
			"inner_secret": "[REDACTED]",
			"info": {
				"bearer_token": "[REDACTED]"
			}
		}
	}`)
	output := r.Redact(input)
	assertJSONSemanticEqual(t, output, expected)
}

func TestRedactor_DefaultPatterns_Array(t *testing.T) {
	r := NewRedactor(true, nil)
	input := []byte(`{
		"users": [
			{"name": "Alice", "password": "p1"},
			{"name": "Bob", "secret": "s1"}
		]
	}`)
	expected := []byte(`{
		"users": [
			{"name": "Alice", "password": "[REDACTED]"},
			{"name": "Bob", "secret": "[REDACTED]"}
		]
	}`)
	output := r.Redact(input)
	assertJSONSemanticEqual(t, output, expected)
}

func TestRedactor_CaseInsensitive(t *testing.T) {
	r := NewRedactor(true, nil)
	input := []byte(`{
		"PASSWORD": "p1",
		"Token": "t1",
		"SeCrEt": "s1",
		"API_KEY": "k1",
		"Bearer": "b1",
		"AUTHORIZATION": "a1"
	}`)
	expected := []byte(`{
		"PASSWORD": "[REDACTED]",
		"Token": "[REDACTED]",
		"SeCrEt": "[REDACTED]",
		"API_KEY": "[REDACTED]",
		"Bearer": "[REDACTED]",
		"AUTHORIZATION": "[REDACTED]"
	}`)
	output := r.Redact(input)
	assertJSONSemanticEqual(t, output, expected)
}

func TestRedactor_NonMatchingKeys(t *testing.T) {
	r := NewRedactor(true, nil)
	input := []byte(`{
		"username": "alice",
		"email": "alice@example.com",
		"id": 12345,
		"active": true
	}`)
	expected := []byte(`{
		"username": "alice",
		"email": "alice@example.com",
		"id": 12345,
		"active": true
	}`)
	output := r.Redact(input)
	assertJSONSemanticEqual(t, output, expected)
}

func TestRedactor_CustomPatterns(t *testing.T) {
	r := NewRedactor(true, []string{"  ssn  ", "credit_card", ""})
	input := []byte(`{
		"ssn": "111-22-3333",
		"credit_card": "4111-1111-1111-1111",
		"password": "unredacted_password"
	}`)
	expected := []byte(`{
		"ssn": "[REDACTED]",
		"credit_card": "[REDACTED]",
		"password": "unredacted_password"
	}`)
	output := r.Redact(input)
	assertJSONSemanticEqual(t, output, expected)
}
