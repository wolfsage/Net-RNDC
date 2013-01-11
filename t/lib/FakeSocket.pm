package
	FakeSocket; # Hide from indexer?

use strict;
use warnings;

use Carp qw(croak);

# Called by Net::RNDC::do
sub new {
	my ($self, %opt) = @_;

	$self->reset;

	for my $arg (qw(PeerAddr)) {
		unless ($opt{$arg}) {
			croak("Required arg $arg missing");
		}

		$self->{$arg} = $opt{$arg};
	}

	return $self;
}

# Actual constructor
sub create {
	my ($class, %opt) = @_;

	# Build up our $sock "package"
	my %obj;

	for my $arg (qw(on_read)) {
		unless ($opt{$arg}) {
			croak("Required arg $arg missing");
		}

		$obj{$arg} = $opt{$arg};
	}

	$obj{on_reset} = $opt{on_reset} if $opt{on_reset};

	$obj{response} = [];

	return bless \%obj, $class;
}

# Reset internal state
sub reset {
	my ($self) = @_;

	$self->{response} = [];
	$self->{PeerAddr} = '';

	$self->{on_reset} && $self->{on_reset}->($self);
}

# Fake IO::Socket::INET::send()
sub send {
	my ($self, $data) = @_;

	$self->{on_read}->($self, $data);

	return length($data);
}

# Fake IO::Socket::INET::recv()
sub recv {
	my ($self) = @_;

	if (@{$self->{response}}) {
		my $data = shift @{$self->{response}};

		$_[1] = $data;

		return '';
	}

	$@ = "No data to recv\n";
	warn "$@";

	return;
}

# Fake IO::Socket::INET::close()
sub close { }

# Add data that we'll send back to the remote end
sub append_response {
	my ($self, $data) = @_;

	push @{$self->{response}}, $data;
}

1;
__END__

=head1 NAME

FakeSocket - Pretend to be L<IO::Socket::INET>-like for testing L<Net::RNDC>.

=head1 SYNOPSIS

  my $sockpkg = FakeSocket->create(
    on_read => sub {
      my ($sock, $data) = @_;

      # Do something with data Net::RNDC just sent us
    },
  );

  my $rndc = Net::RNDC->new(sock => $sockpkg);
  $rndc->do('status');

=head1 DESCRIPTION

This package pretends to be an L<IO::Socket::INET>-like package and allows users 
to provide a hook for when the L<Net::RNDC> client sends data to this package 
thinking it's a socket.

This is useful to test L<Net::RNDC> without needing to fork and run a separate 
socket server or attempt to go async.

=head2 Constructor

=head3 create

  FakeSocket->create(%args);

Required Arguments:

=over 4

=item *

B<on_read> - A hook (subroutine) that is called with the L<FakeSocket> object 
and the data that l<Net::RNDC> called send() with. This should be the main 
driver of how L<FakeSocket> behaves in response to L<Net::RNDC>.

=back

Optional Arguments:

=over 4

=item *

B<on_reset> - A hook (subroutine) that is called each time C<< $rndc->do() >> is 
called that can be used to reset state to run new tests.

=back

=head2 Methods

=head3 append_response

  $sock->append_response($packet->data);

This should be used by tests to signal that data should be added to the outgoing 
send queue that will be read in by L<Net:RNDC>.

=head3 reset

  $sock->reset;

This is called whenever L</new> is called on an existing 
L<FakeSocket> object. It should handle resetting state for the most part, but is 
provided as part of the public interface in the event that more fine grained 
control is wanted.

=head1 SEE ALSO

t/00_rndc.t - An example of how to use this with L<Net::RNDC::Session> to mimick 
L<Net::RNDC> talking to an actual server

=head1 AUTHOR

Matthew Horsfall (alh) <WolfSage@gmail.com>

=head1 LICENSE

You may distribute this code under the same terms as Perl itself.

=cut
