# $Id: AuthenFile.pm,v 1.6 2002/10/23 15:44:41 reggers Exp $

package Apache::AuthenFile;

$Apache::AuthenFile::VERSION = '0.01';

use Apache ();
use Apache::Constants qw(OK AUTH_REQUIRED DECLINED SERVER_ERROR);
use IO::File;
use Carp;

use strict;

sub handler {
    my $r = shift;

    # Continue only if the first request.

    return OK unless $r->is_initial_req;

    # Get the password, userid and password file

    my ($res, $pass) = $r->get_basic_auth_pw;
    return $res if $res;

    my $user=$r->connection->user;
    return AUTH_REQUIRED unless $user;

    # Gotta have a password file that we can read.

    my($file, $fh);
    croak "No 'AuthenFile' provided!"
	unless $file=$r->dir_config("AuthenFile");
    croak "Cannot read '$file'!"
	unless $fh=new IO::File("< $file");

    # walk through the file looking for a match

    while ($_=<$fh>) {
	chop($_);
	my($id,$cipher)=split(/:/,$_);
	next unless ($user eq $id);
	next unless (crypt($pass,$cipher) eq $cipher);
	$fh->close(); return OK;
    }

    $fh->close();
    $r->note_basic_auth_failure;
    return AUTH_REQUIRED;
}

1;

__END__

=head1 NAME

Apache::AuthenFile - Authentication with a "password" file

=head1 SYNOPSIS

 # Authentication in .htaccess/httpd.conf

 AuthName "User Authentication"
 AuthType Basic

 # authenticate using a password file

 PerlAuthenHandler Apache::AuthenFile
 PerlSetVar AuthenFile /some/file

 # constraints

 require valid-user
 # require user larry moe curly

=head1 DESCRIPTION

This Perl module allows authentication against a "password" file --
each line in the file consists of a "B<userid>:B<cipher>" where the
B<cipher> is a standard Unix crypt of the user's password. The module
scans the file sequentially to search for a match.

The B<AuthenFile> parameter specifies the password file that should be
searched.

=head1 BEWARE

The search of the password file is sequential. Performance is an issue
for large password files -- use the B<AuthenDBMFile> method instead.

=head1 SEE ALSO

L<Apache>, L<mod_perl>, L<AuthenDBMFile>

=head1 AUTHOR

Reg Quinton E<lt>reggers@ist.uwaterloo.caE<gt>, 18-Oct-2002.

=head1 COPYRIGHT

The Apache::AuthenFile module is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

=cut
