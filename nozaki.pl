#!/usr/bin/env perl

use JSON;
use 5.018;
use strict;
use warnings;
use IO::Socket;
use lib "./lib/";
use Engine::Fuzzer;
use Functions::Helper;
use Parallel::ForkManager;
use Getopt::Long qw(:config no_ignore_case);


sub fuzzer_thread {
    my ($target, $methods, $agent, $headers, $accept, $timeout, $return, $payload, $json, $delay, $exclude) = @_;

    my $client = IO::Socket::INET->new(
        Proto       =>  'tcp',
        PeerAddr    =>  'localhost',
        PeerPort    =>  8888,
    ) || die "[Thread] error connecting to localhost:8888";

    my $fuzzer = Engine::Fuzzer -> new (
            useragent   => $agent,
            timeout     => $timeout,
            headers     => $headers
    );
    
    my @verbs = split (/,/, $methods);
    my @valid_codes = split /,/, $return || "";
    my @invalid_codes = split /,/, $exclude || "";
    while (defined(my $resource = <$client>))
    {
        chomp($resource);
        my $endpoint = $target . $resource;
        for my $verb (@verbs) {
            my $result = $fuzzer -> fuzz ($endpoint, $verb, $payload, $accept);

            my $status = $result -> {Code};
            next if grep(/^$status$/, @invalid_codes) || ($return && !grep(/^$status$/, @valid_codes));
            
            my $printable = $json ? encode_json($result) : sprintf(
                "Code: %d | URL: %s | Method: %s | Response: %s | Length: %s",
                $status, $result -> {URL}, $result -> {Method},
                $result -> {Response}, $result -> {Length}
            );

            print $printable . "\n";
            sleep($delay);
        }
    }
}

sub main {
    my ($target, $return, $payload, %headers, $accept, $json, $exclude);
    my $agent    = "Nozaki CLI / 0.2.1";
    my $delay    = 0;
    my $timeout  = 10;
    my $wordlist = "wordlists/default.txt";
    my $methods  = "GET,POST,PUT,DELETE,HEAD,OPTIONS,TRACE,PATCH,PUSH";
    my $tasks    = 10;

    GetOptions (
        "A|accept=s"   => \$accept,
        "u|url=s"      => \$target,
        "w|wordlist=s" => \$wordlist,
        "m|method=s"   => \$methods,
        "d|delay=i"    => \$delay,
        "t|timeout=i"  => \$timeout,
        "a|agent=s"    => \$agent,
        "r|return=i"   => \$return,
        "p|payload=s"  => \$payload,
        "j|json"       => \$json,
        "H|header=s%"  => \%headers,
        "T|tasks=i"    => \$tasks,
        "e|exclude=s"  => \$exclude,
    ) or die ( return Functions::Helper -> new() );

    return Functions::Helper -> new() unless $target && $wordlist;
    
    open (my $file, "<", $wordlist) || die "$0: Can't open $wordlist";

    my $server = IO::Socket::INET -> new(
        Proto       => 'tcp',
        LocalAddr   => 'localhost',
        LocalPort   => 8888,
        Reuse       => 1,
    ) || die "$0: Can't listen on localhost:8888";
    $server -> listen($tasks);

    my $threadmgr = Parallel::ForkManager -> new($tasks);

    $threadmgr -> set_waitpid_blocking_sleep(0);
    THREADS:
    for (1 .. $tasks) {
        $threadmgr -> start() and next THREADS;
        
        fuzzer_thread($target, $methods, $agent, \%headers, $accept, $timeout, $return, $payload, $json, $delay, $exclude);
        
        $threadmgr -> finish();
    }

    my @clients;
    while (@clients < $tasks) {
        my $client = $server->accept();
        push @clients, $client if $client;
    }

    my $current = 0;
    while (<$file>) {
        $clients[$current] -> send($_);
        ($current += 1) %= $tasks;
    }

    $_ -> close() for @clients;
    
    $threadmgr -> wait_all_children();
    
    close $file;
    
    return 0;
}

exit main();
