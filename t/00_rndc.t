#!/usr/bin/perl

use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin/lib";

use Test::More;
use Test::Exception;

use FakeSocket;

use Net::RNDC;

use Carp qw(croak);

my $key = 'abcd';

my $rndc = Net::RNDC->new();
ok($rndc, 'new() with no args');

throws_ok { $rndc->do('status') }
	qr/Missing required argument 'key'/,
	"do() without 'key' fails";

throws_ok { $rndc->do('status', key => 'aabc') }
	qr/Missing required argument 'host'/,
	"do() without 'host' fails";

# So we don't have to pass to each test below
$rndc = Net::RNDC->new(key => 'abcd', host => '127.0.0.1');

throws_ok { $rndc->do('status', sock => 'blah') }
	qr/Package 'blah' has no 'new' method/,
	"do() with bad 'sock' fails";

{ package Blah; sub new { return bless {}, shift; } }
throws_ok { $rndc->do('status', sock => 'Blah') }
	qr/Object returned from 'Blah->new\(\)' has no 'send' method/,
	"do() with bad 'sock' fails";

eval "{ package Blah; sub send { } }";
throws_ok { $rndc->do('status', sock => 'Blah') }
	qr/Object returned from 'Blah->new\(\)' has no 'recv' method/,
	"do() with bad 'sock' fails";

eval "{ package Blah; sub recv { } }";
throws_ok { $rndc->do('status', sock => 'Blah') }
	qr/Object returned from 'Blah->new\(\)' has no 'close' method/,
	"do() with bad 'sock' fails";

# A socket 'class' that uses Net::RNDC::Session as a server internally to
# make sure Net::RNDC logic works correctly
my @data;

my $sockpkg = FakeSocket->create(
	on_read => sub {
		my ($sock, $data) = @_;

		if (!$sock->{_session}) {
			$sock->{_session} = Net::RNDC::Session->new(
				key         => $key,
				is_server   => 1,
				command     => "birdy",

				want_write => sub {
					my $s = shift;

					$sock->append_response(shift);

					$s->next;
				},

				want_read => sub {},

				want_finish => sub {},

				# Hrm server error. We have to generate a packet
				# Net::RNDC::Session as a server should be 
				# smart enough to generate a packet error 
				# response for us and send it out if possible
				want_error => sub {
					my $s = shift;
					my $err = shift;

					my $pkt = Net::RNDC::Packet->new(
						key => $key,
					);

					$pkt->{data}->{_data}{_err} = $err;

					$sock->append_response($pkt->data);

					# Cheating so hard... ugh.
					$s->_state('want_write');

					$s->next;
				}
			);

			$sock->{_session}->start;
		}

		$sock->{_session}->next($data);

		# Let's track this packet from Net::RNDC too in case we want to 
		# inspect it in tests
		push @data, $data;
	},

	# Called on each call to do()
	on_reset => sub {
		my ($sock) = @_;

		delete $sock->{_session};

		@data = ();
	}
);

$rndc = Net::RNDC->new(
	key  => $key,
	sock => $sockpkg,
	host => '127.0.0.1',
);
ok($rndc, 'Got an rndc object');

# Normal do
ok($rndc->do('status'), 'do(\'status\') works');
is($rndc->error, '', 'no error');
is($rndc->response, 'birdy', "Got correct response from server");
is($sockpkg->{PeerAddr}, '127.0.0.1:953', 'Host is correct in socket package');

# Check packets Net::RNDC generated
is(@data, 2, 'Got two packets from Net::RNDC');

# Should really do deeper checking here eventually maybe
my $pkt = Net::RNDC::Packet->new(key => $key);
ok($pkt->parse(shift @data), 'Net::RNDC generated parsable packet');
is($pkt->{data}{_ctrl}{_nonce}, undef, 'Initial packet has no nonce');

ok($pkt->parse(shift @data), 'Net::RNDC generated parsable packet');
ok($pkt->{data}{_ctrl}{_nonce}, 'Second packet has nonce');
is($pkt->{data}{_data}{type}, 'status', 'packet has correct command');

# Do with different command (test undef here as well)
ok($rndc->do(), 'do() works');
is($rndc->error, '', 'no error');
is($rndc->response, 'birdy', "Got correct response from server");

# Check packets Net::RNDC generated
is(@data, 2, 'Got two packets from Net::RNDC');

$pkt = Net::RNDC::Packet->new(key => $key);
ok($pkt->parse(shift @data), 'Net::RNDC generated parsable packet');
is($pkt->{data}{_ctrl}{_nonce}, undef, 'Initial packet has no nonce');

ok($pkt->parse(shift @data), 'Net::RNDC generated parsable packet');
ok($pkt->{data}{_ctrl}{_nonce}, 'Second packet has nonce');
is($pkt->{data}{_data}{type}, 'null', 'packet has correct command');


# Do with different host
ok($rndc->do('status', host => '10.0.0.1'), 'do(host => ..) works');
is($rndc->error, '', 'no error');
is($rndc->response, 'birdy', "Got correct response from server");
is($sockpkg->{PeerAddr}, '10.0.0.1:953', 'Host is correct in socket package');

# Do with different port
ok($rndc->do('status', port => 5), 'do(port => ..) works');
is($rndc->error, '', 'no error');
is($rndc->response, 'birdy', "Got correct response from server");
is($sockpkg->{PeerAddr}, '127.0.0.1:5', 'Host is correct in socket package');

# do() with bad key
ok(! $rndc->do('status', key => 'meh'), 'do() with bad key fails');
like($rndc->error, qr/Couldn't validate packet/, 'Could not verify client request');
is($rndc->response, '', "Got empty response");

$rndc = Net::RNDC->new(key => $key, host => '127.0.0.1');
ok($rndc, 'Got new blank rndc with $key');	

# do() with sock
ok($rndc->do('status', sock => $sockpkg), 'do(sock => ...) works');
is($rndc->error, '', 'no error');
is($rndc->response, 'birdy', "Got correct response");

done_testing;
