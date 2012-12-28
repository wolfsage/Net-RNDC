package Net::RNDC::Session;

use strict;
use warnings;

use Net::RNDC::Packet;

use Carp qw(croak);

# Controls the flow in next(). undef means next() should never
# be called if we've reached this state
my %states = (
	start        => '_got_start',
	want_read    => '_got_read',
	want_write   => '_got_write',
	want_error   => undef,
	want_finish  => undef,
);

sub new {
	my ($class, %args) = @_;

	my @required_subs = qw(
		want_read
		want_write
		want_finish
		want_error
	);

	my @optional_subs = qw(
	);

	my @required_args = qw(
		key
		command
	);

	my @optional_args = qw(
		is_client
		is_server
	);

	for my $r (@required_subs, @required_args) {
		unless (exists $args{$r}) {
			croak("Missing required argument '$r'");
		}
	}

	for my $r (@required_subs, @optional_subs) {
		next unless exists $args{$r};

		unless ((ref $args{$r} || '') eq 'CODE') {
			croak("Argument '$r' is not a code ref");
		}
	}

	unless (exists $args{is_client} || exists $args{is_server}) {
		croak("Argument 'is_client' or 'is_server' must be defined");
	}

	if (exists $args{is_client} && exists $args{is_server}) {
		croak("Argument 'is_client' cannot be mixed with 'is_server'");
	}

	my %obj = map {
		$_ => $args{$_}
	} grep { exists $args{$_} } (@required_subs, @optional_subs, @required_args, @optional_args);

	if (exists $args{is_client}) {
		$obj{is_client} = 1;
	} else {
		$obj{is_server} = 1;
	}

	# Soon?
	if ($obj{is_server}) {
		croak("Argument 'is_server' not yet supported");
	}

	my $obj = bless \%obj, $class;

	# Base state
	$obj->_init;

	return $obj;
}

# Maybe open up to public as reset()?
sub _init {
	my ($self) = @_;

	# Have we sent our syn/ack opener?
	$self->{nonce} = 0;

	$self->_state('start');
}

# Set/retrieve state
sub _state {
	my ($self, $state) = @_;

	if ($state) {
		unless (exists $states{$state}) {
			croak("Unknown state $state requested");
		}

		$self->{state} = $state;
	}

	return $self->{state};
}

sub _is_client { return $_[0]->{'is_client'} }
sub _is_server { return $_[0]->{'is_server'} }
sub _key       { return $_[0]->{'key'}       }
sub _nonce     { return $_[0]->{'nonce'}     }
sub _command   { return $_[0]->{'command'}   }

# Entry point. Always.
sub start {
	my ($self) = @_;

	unless (my $state = $self->_state eq 'start') {
		croak("Attempt to re-use an existing session in state '$state'");
	}

	$self->next;
}

# Move things along. Pass in data if needed
sub next {
	my ($self, $data) = @_;

	my $sub = $states{$self->_state};

	unless ($sub) {
		croak("next() called on bad state '" . $self->_state . "'");
	}

	$self->$sub($data);

	return;
}

# _got subs are called after a want_* sub has been called and next() has been used

# Starting out
sub _got_start {
	my ($self, $data) = @_;

	if ($self->_is_client) {
		# Client step 1: send a request packet with no data section
		my $packet = Net::RNDC::Packet->new(
			key => $self->_key,
		);

		$self->_state('want_write');

		return $self->_run_want('want_write', $packet->data, $packet);
	} else {
		$self->_state('want_read');

		return $self->_run_want('want_read');
	}
}

sub _got_read {
	my ($self, $data) = @_;

	if ($self->_is_client) {
		my $packet = Net::RNDC::Packet->new(key => $self->_key);

		if (! $self->_nonce) {
			# Client step 2: Parse response, get nonce
			$self->{nonce} = 1;

			if (!$packet->parse($data)) {
				$self->_state('want_error');

				return $self->_run_want('want_error', $packet->error);
			}

			my $nonce = $packet->{data}->{_ctrl}{_nonce};

			# Client step 3: Send request with nonce/data section
			my $packet2 = Net::RNDC::Packet->new(
				key => $self->_key,
				nonce => $nonce,
				data => {type => $self->_command},
			);

			$self->_state('want_write');

			return $self->_run_want('want_write', $packet2->data);
		} else {
			# Client step 4: Read response to command
			if (!$packet->parse($data)) {
				$self->_state('want_error');

				return $self->_run_want('want_error', $packet->error);
			}

			my $response = $packet->{data}{_data}{text} || 'command success';

			$self->_state('want_finish');

			return $self->_run_want('want_finish', $response);
		}
	}		
}

sub _got_write {
	my ($self) = @_;

	# As a client, after every write we expect a read
	if ($self->_is_client) {
		$self->_state('want_read');

		return $self->_run_want('want_read');
	}
}

# Run the requested want_* sub
sub _run_want {
	my ($self, $sub, @args) = @_;

	my $ref = $self->{$sub};

	$ref->($self, @args);
}

sub DESTROY {
	warn "Destroyed\n";
}

1;
__END__

=head1 NAME

Net::RNDC::Session - Helper package to manage the RNDC 4-packet session

=head1 SYNOPSIS

To use synchronously:

  use IO::Socket::INET;
  use Net::RNDC::Session;

  my $c = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1:953',
  ) or die "Failed to create a socket: $@ ($!)";

  # Our response
  my $response;

  my $session = Net::RNDC::Session->new(
    key         => 'abcd',
    command     => 'status',
    is_client   => 1,

    want_write =>  sub { my $s = shift; $c->send(shift); $s->next; },
    want_read  =>  sub { my $s = shift; my $b; $c->recv($b, 4096); $s->next($b); },
    want_finish => sub { my $s = shift; $response = shift; },
    want_error =>  sub { my $s = shift; my $err = shift; die "Error: $err\n"; },
  );

  # Since we call next() in want_read/want_write above, this will do everything
  $session->start;

  print "Response: $response\n";

To use asynchronously (for example, with IO::Async):

TBD

=head1 DESCRIPTION

This package is intended to provide the logic for a RNDC session which is used 
to run a single command against a remote server and get a response. See 
L<SESSION> below for a description of the RNDC client session logic.

There is no socket logic here, that must be provided to this class through the 
constructor in the various C<want_*> methods. This allows for 
synchronous/asynchronous use with a little work.

This package does generate and parse L<Net::RNDC::Packet>s, but the L<want_read> 
and L<want_write> methods allow you to peak at this data before it's parsed and 
before it's sent to the remote end to allow slightly more fine-grained control.

To manage the entire process yourself, use L<Net::RNDC::Packet>.

=head1 SESSION

TBD

=head1 AUTHOR

Matthew Horsfall (alh) <WolfSage@gmail.com>

=head1 LICENSE

You may distribute this code under the ssame terms as Perl itself.

=cut
