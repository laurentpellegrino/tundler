package main

import "testing"

func TestExtractPassageToken(t *testing.T) {
	// A RefreshServiceResponse body shaped like the real one: a jobs array whose
	// vpn_passage block carries the discovery token.
	body := []byte(`{"action":"Process","data":[
		{"Data":{"productInstance":"..."},"Job":"APPLYPRODUCTINSTANCE"},
		{"Data":{"ConnectToken":"x"},"Job":"OXYGENBIND"},
		{"Data":{"vpn_passage":{"http_code":200,"response":{"status":{"code":0},"data":{
			"token":{"access_token":"the.jwt.value","refresh_token":"r"},
			"credentials":{"device_udid":"U1.x.nlk401.y","device_password":"p"}
		}}}}}
	],"status":0}`)
	tok, err := extractPassageToken(body)
	if err != nil {
		t.Fatalf("extractPassageToken: %v", err)
	}
	if tok != "the.jwt.value" {
		t.Fatalf("got token %q, want %q", tok, "the.jwt.value")
	}
}

func TestExtractPassageTokenMissing(t *testing.T) {
	// A response with no vpn_passage block must error, not return "".
	body := []byte(`{"action":"Process","data":[{"Data":{"ConnectToken":"x"},"Job":"OXYGENBIND"}]}`)
	if _, err := extractPassageToken(body); err == nil {
		t.Fatal("expected an error when vpn_passage is absent")
	}
}

func TestExtractPassageTokenError(t *testing.T) {
	// The backend's error shape (data is a string) must not panic and must error.
	body := []byte(`{"action":"Error","data":"cde=-727,msg=JsonEncodingError","status":-727}`)
	if _, err := extractPassageToken(body); err == nil {
		t.Fatal("expected an error for an error-shaped response")
	}
}
