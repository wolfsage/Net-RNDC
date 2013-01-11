package Net::RNDC;
# ABSTRACT: Speak the BIND RNDC protocol

use strict;
use warnings;

use UNIVERSAL ();

use Carp qw(croak);

use Net::RNDC::Session;

my $Sock;

BEGIN {
	eval 'use IO::Socket::INET6;';

	if ($@) {
		eval 'use IO::Socket::INET;';

		die $@ if $@;

		$Sock = 'IO::Socket::INET';
	} else {
		$Sock = 'IO::Socket::INET6';
	}
}

# Required for new()
my @required_args = qw(
);

# Optional for new()/do()
my @optional_args = qw(
	key
	host
	port
	sock
);

sub new {
	my ($class, %args) = @_;

	my %obj = $class->_parse_args(%args);

	return bless \%obj, $class;
}

sub _parse_args {
	my ($class, %args) = @_;

	for my $r (@required_args) {
		unless ($args{$r}) {
			croak("Missing required argument '$r'");
		}
	}

	$args{port} ||= 953;
	$args{sock} ||= $Sock;

	return map {
		$_ => $args{$_}
	} grep { $args{$_} } (@required_args, @optional_args);
}

sub _check_do_args {
	my ($self, %args) = @_;

	for my $r (qw(key host)) {
		unless ($args{$r}) {
			croak("Missing required argument '$r'");
		}
	}

	unless(UNIVERSAL::can($args{sock}, 'new')) {
		croak("Package '$args{sock}' has no 'new' method");
	}	
}

sub do {
	my ($self, $command, %override) = @_;

	$self->{response} = $self->{error} = '';

	my $host = $self->{host};
	my $port = $self->{port};
	my $key  = $self->{key};
	my $sock = $self->{sock};

	if (%override) {
		my %args = $self->_parse_args(
			host => $host,
			port => $port,
			key  => $key,
			sock => $sock,
			%override,
		);

		$host = $args{host};
		$port = $args{port};
		$key  = $args{key};
		$sock = $args{sock};
	}

	$self->_check_do_args(
		host => $host,
		port => $port,
		key  => $key,
		sock => $sock,
	);

	my $c = $sock->new(
		PeerAddr => "$host:$port",
	);

	unless ($c) {
		$self->{error} = "Failed to create a $sock: $@ ($!)";

		return 0;
	}

	for my $meth (qw(send recv close)) {
		unless (UNIVERSAL::can($c, $meth)) {
			croak("Object returned from '$sock->new()' has no '$meth' method");
		}
	}

	# Net::RNDC::Session does all of the work
	my $sess = Net::RNDC::Session->new(
		key         => $key,
		command     => $command,
		is_client   => 1,

		want_write => sub {
			my $s = shift;

			$c->send(shift);

			$s->next;
		},

		want_read => sub {
			my $s = shift;

			my $buff;

			$c->recv($buff, 4096);

			$s->next($buff);
		},

		want_finish => sub {
			my $s = shift;
			my $res = shift;

			$self->{response} = $res;
		},

		want_error => sub {
			my $s = shift;
			my $err = shift;

			$self->{error} = $err;
		}
	);

	# Work!
	$sess->start;

	$c->close;

	if ($self->response) {
		return 1;
	} else {
		return 0;
	}
}

sub response {
	my ($self) = @_;

	return $self->{response};
}

sub error {
	my ($self) = @_;

	return $self->{error};
}

1;
__END__;

=head1 NAME

Net::RNDC - Speak the BIND Remote Name Daemon Control (RNDC) V1 protocol

=head1 SYNOPSIS

Simple synchronous command/response:

  use Net::RNDC;

  my $rndc = Net::RNDC->new(
    host => '127.0.0.1',
    port => 953,         # Defaults to 953
    key  => 'abcd',
  );

  if (!$rndc->do('status')) {
    die "RNDC failed: " . $rndc->error;
  }

  print $rndc->response;

All arguments to new() are allowed in do:

  my $rndc = Net::RNDC->new();

  my $key = 'abcd';

  for my $s (qw(127.0.0.1 127.0.0.2)) {
    if (!$rndc->do('status', key => $key, host => $s)) {
      my $err = $rndc->error;
    } else {
      my $resp = $rndc->response;
    }
  }

=head1 DESCRIPTION

This package provides a synchronous, easy to use interface to the RNDC V1 
protocol. For more mid-level control, see L<Net::RNDC::Session>, and for 
absolute control, L<Net::RNDC::Packet>.

=head2 Constructor

=head3 new

  Net::RNDC->new(%args);

Optional Arguments:

=over 4

=item *

B<key> - The Base64 encoded HMAC-MD5 private key to use.

=item *

B<host> - The hostname/IP of the remote server to connect to. If 
L<IO::Socket::INET6> is installed, IPv6 support will be enabled.

=item *

B<port> - The port to connect to. Defaults to I<953>.

=item *

B<sock> - A package, like L<IO::Socket::INET>, that provides a C<new> function 
which returns an object capable of performing C<send>, C<recv>, and C<close>, 
and behaving similar to them. See C<< perldoc -f >> for each of the methods 
above to see how they should behave. Defaults to L<IO::Socket::INET6> if 
available, otherwise C<IO::Socket::INET>. The C<new> function should accept one 
parameter - B<PeerAddr> - which will be a I<hostname:port> string.

=back

=head2 Methods

=head3 do

  $rndc->do($command);

  $rndc->do($commands, %args);

Connects to the remote nameserver configured in L</new> or passed in to  
B<%args> and sends the specified command.

Returns 1 on success, 0 on failure.

Arguments:

=over 4

=item *

B<$command> - The RNDC command to run. For example: C<status>.

=back

Optional Arguments - See L</new> above.

=head3 error

  $rndc->error;

Returns the last string error from a call to L</do>, if any. Only set if 
L</do> returns 0.

=head3 response

  $rndc->response;

Returns the last string response from a call to L</do>, if any. Only set if 
L</do> returns 1.

=head1 SEE ALSO

L<Net::RNDC::Session> - Manage the 4-packet RNDC session

L<Net::RNDC::Packet> - Low level RNDC packet manipulation.

=head1 AUTHOR

Matthew Horsfall (alh) <WolfSage@gmail.com>

=head1 LICENSE

You may distribute this code under the same terms as Perl itself.

=cut
