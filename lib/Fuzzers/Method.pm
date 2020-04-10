package Fuzzers::Method;

use strict;
use warnings;
use HTTP::Request;
use LWP::UserAgent;

sub new {
    my ($self, $endpoint, $header) = @_;

    my $userAgent = LWP::UserAgent -> new();

    my @verbs = (
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE", "PATCH", "SUBSCRIBE", "MOVE", 
        "REPORT", "UNLOCK", "%s%s%s%s", "PURGE", "POLL", "NOTIFY", "SEARCH", "1337", "CATS", "*", "DATA", "HEADERS",
        "PRIORITY", "RST_STREAM", "SETTINGS", "PUSH_PROMISE", "PING",  "GOAWAY", "WINDOW_UPDATE", "CONTINUATION"
    );

    foreach my $verb (@verbs) {
        my $request     = new HTTP::Request($verb, $endpoint, $header);
        my $response    = $userAgent -> request($request);
        my $httpCode    = $response -> code();
        my $httpMessage = $response -> message();

        print "[-] -> [$httpCode] | $endpoint \t [$verb] - $httpMessage\n";        
    }

    return 1;
}

1;