
###################################################################################
#
#   Apache::AuthenNTLM - Copyright (c) 2002 Gerald Richter / ECOS
#
#   You may distribute under the terms of either the GNU General Public
#   License or the Artistic License, as specified in the Perl README file.
#
#   THIS PACKAGE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR
#   IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
#   WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
#
#   $Id: AuthenNTLM.pm,v 1.13 2002/04/09 06:52:38 richter Exp $
#
###################################################################################


package Apache::AuthenNTLM ;

use strict ;
use vars qw{$cache $VERSION %msgflags1 %msgflags2 %msgflags3 %invflags1 %invflags2 %invflags3} ;

$VERSION = 0.15 ;

my $debug = 0 ;

$cache = undef ;

use MIME::Base64 () ;
use Authen::Smb 0.92 ;

#use Crypt::SmbHash ;
#use Digest::MD4 ;
use Apache::Constants qw(:common);

%msgflags1 = ( 0x01 => "NEGOTIATE_UNICODE",
       0x02 => "NEGOTIATE_OEM",
       0x04 => "REQUEST_TARGET",
       0x10 => "NEGOTIATE_SIGN",
       0x20 => "NEGOTIATE_SEAL",
       0x80 => "NEGOTAITE_LM_KEY",
     );

%msgflags2 = ( 0x02 => "NEGOTIATE_NTLM",
       0x40 => "NEGOTIATE_LOCAL_CALL",
       0x80 => "NEGOTIATE_ALWAYS_SIGN",
     );

%msgflags3 = ( 0x01 => "TARGET_TYPE_DOMAIN",
       0x02 => "TARGET_TYPE_SERVER",
     );

%invflags1 = ( "NEGOTIATE_UNICODE" => 0x01,
       "NEGOTIATE_OEM"     => 0x02,
       "REQUEST_TARGET"    => 0x04,
       "NEGOTIATE_SIGN"    => 0x10,
       "NEGOTIATE_SEAL"    => 0x20,
       "NEGOTAITE_LM_KEY"  => 0x80,
     );

%invflags2 = ( "NEGOTIATE_NTLM"        => 0x02,
       "NEGOTIATE_LOCAL_CALL"  => 0x40,
       "NEGOTIATE_ALWAYS_SIGN" => 0x80,
     );

%invflags3 = ( "TARGET_TYPE_DOMAIN" => 0x01,
       "TARGET_TYPE_SERVER" => 0x02,
     );

sub get_config

    {
    my ($self, $r) = @_ ;

    return if ($self -> {smbpdc}) ; # config already setup

    $debug = $r -> dir_config ('ntlmdebug') || 0 ;
    $debug = $self -> {debug} = lc($debug) eq 'on' || $debug == 1?1:0 ;

    my @config = $r -> dir_config -> get ('ntdomain') ;

    foreach (@config)
        {
        my ($domain, $pdc, $bdc) = split /\s+/ ;
        $domain = lc ($domain) ;
        $self -> {smbpdc}{$domain} = $pdc ;
        $self -> {smbbdc}{$domain} = $bdc ;
        print STDERR "AuthenNTLM: Config Domain = $domain  pdc = $pdc  bdc = $bdc\n" if ($debug) ; 
        }

    $self -> {defaultdomain} = $r -> dir_config ('defaultdomain') || '' ;
    $self -> {authtype} = $r -> auth_type || 'ntlm,basic' ;
    $self -> {authname} = $r -> auth_name || ''  ;
    my $autho = $r -> dir_config ('ntlmauthoritative') || 'on' ;
    $self -> {ntlmauthoritative} = lc($autho) eq 'on' || $autho == 1?1:0 ;
    $autho = $r -> dir_config ('basicauthoritative') || 'on' ;
    $self -> {basicauthoritative} = lc($autho) eq 'on' || $autho == 1?1:0 ;
	
    $self -> {authntlm} = 0 ;
    $self -> {authbasic} = 0 ;

    $self -> {authntlm} = 1 if ($self -> {authtype} =~ /(^|,)ntlm($|,)/i) ;
    $self -> {authbasic} = 1 if ($self -> {authtype} =~ /(^|,)basic($|,)/i) ;
    if ($debug)
	{
	print STDERR "AuthenNTLM: Config Default Domain = $self->{defaultdomain}\n"  ; 
	print STDERR "AuthenNTLM: Config AuthType = $self->{authtype} AuthName = $self->{authname}\n"  ; 
	print STDERR "AuthenNTLM: Config Auth NTLM = $self->{authntlm} Auth Basic = $self->{authbasic}\n"  ; 
	print STDERR "AuthenNTLM: Config NTLMAuthoritative = ",  $self -> {ntlmauthoritative}?'on':'off', "  BasicAuthoritative = ",  $self -> {basicauthoritative}?'on':'off', "\n"  ; 
	}
    }


sub get_nonce

    {
    my ($self, $r) = @_ ;

    # reuse connection if possible
    return $self -> {nonce} if ($self -> {nonce} && $self -> {smbhandle}) ;

    my $nonce = '12345678' ;
    my $domain  = lc ($self -> {domain}) ;
    my $pdc     = $self -> {smbpdc}{$domain} ;
    my $bdc     = $self -> {smbbdc}{$domain} ;

    $self -> {nonce} = undef ;
    
    print STDERR "AuthenNTLM: Connect to pdc = $pdc bdc = $bdc domain = $domain\n" if ($debug) ;
    $self -> {smbhandle} = Authen::Smb::Valid_User_Connect ($pdc, $bdc, $domain, $nonce) ;
    
    if (!$self -> {smbhandle}) 
        {
        $r->log_reason("Connect to SMB Server faild (pdc = $pdc bdc = $bdc domain = $domain) for " . $r -> uri) ;
        return undef ;
        }
   
    
    return $self -> {nonce} = $nonce ;
    }
    


sub verify_user

    {
    my ($self, $r) = @_ ;

    if (!$self -> {smbhandle})
        {
        $r->log_reason("SMB Server connection not open in state 3 for " . $r -> uri) ;
        return ;
        }

    my $rc ;

    print STDERR "AuthenNTLM: Verify user $self->{username} via smb server\n" if ($debug) ;
    if ($self -> {basic})
	{
	$rc = Authen::Smb::Valid_User_Auth ($self -> {smbhandle}, $self->{username}, $self -> {password}) ;
	}
    else
	{
	$rc = Authen::Smb::Valid_User_Auth ($self -> {smbhandle}, $self->{username}, $self -> {usernthash}, 1, $self->{userdomain}) ;
	}

    if ($rc == &Authen::Smb::NTV_LOGON_ERROR)
        {
        $r->log_reason("Wrong password/user (rc=$rc): $self->{userdomain}\\$self->{username} for " . $r -> uri) ;
        print STDERR "AuthenNTLM: rc = $rc  ntlmhash = $self->{usernthash}\n" if ($debug) ; 
        return ;
        }

    if ($rc)
        {
        $r->log_reason("SMB Server error $rc for " . $r -> uri) ;
        return ;
        }

    return 1 ;
    }


sub map_user

    {
    my ($self, $r) = @_ ;

    return "$self->{userdomain}\\$self->{username}" ;
    }



sub substr_unicode 
    {
    my ($data, $off,  $len) = @_ ;

    my $i = 0 ; 
    my $end = $off + $len ;
    my $result = '' ;
    for ($i = $off ; $i < $end ; $i += 2)
        {# for now we simply ignore high order byte
        $result .=  substr ($data, $i,  1) ;
        }

    return $result ;
    }


sub get_msg_data

    {
    my ($self, $r) = @_ ;

    my $auth_line = $r -> header_in ($r->proxyreq ? 'Proxy-Authorization'
                                    : 'Authorization') ;

    $self -> {ntlm}  = 0 ;
    $self -> {basic} = 0 ;

    print STDERR "AuthenNTLM: Authorization Header ", defined($auth_line)?$auth_line:'<not given>', "\n" if ($debug) ;
    if ($self -> {authntlm} && ($auth_line =~ /^NTLM\s+(.*?)$/i)) 
	{
	$self -> {ntlm} = 1 ;
	}
    elsif ($self -> {authbasic} && ($auth_line =~ /^Basic\s+(.*?)$/i)) 
	{
	$self -> {basic}  = 1 ;
	}
    else
	{
	return undef ;
	}

    my $data = MIME::Base64::decode($1) ;


    if ($debug)
        {
        print STDERR "AuthenNTLM: Got: " ;
        for (my $i = 0; $i < length($data); $i++)
            {
            printf STDERR "%x ", unpack('C', substr($data, $i, 1)) ;
            }
        print STDERR "\n" ;
        }

    return $data ;
    }



sub get_msg

    {
    my ($self, $r) = @_ ;

    my $data = $self -> get_msg_data ($r) ;
    return undef if (!$data) ;

    if ($self -> {ntlm})
        {
        my ($protocol, $type) = unpack ('Z8C', $data) ;
        return $self -> get_msg1 ($r, $data) if ($type == 1) ;
        return $self -> get_msg3 ($r, $data) if ($type == 3) ;
        return $type ;
        }
    elsif ($self -> {basic})
        {
        return $self -> get_basic ($r, $data) ;
        }
    return undef ;
    }



sub get_msg1

    {
    my ($self, $r, $data) = @_ ;

    my ($protocol, $type, $zero, $flags1, $flags2, $zero2, $dom_len, $x1, $dom_off, $x2, $host_len, $x3, $host_off, $x4) = unpack ('Z8Ca3CCa2vvvvvvvv', $data) ;
    my $host   = $host_off?substr ($data, $host_off, $host_len):'' ;
    my $domain = $dom_off?substr ($data, $dom_off,  $dom_len):'' ;

    $self -> {domain} = $dom_len?$domain:$self -> {defaultdomain} ;
    $self -> {host}   = $host_len?$host:'' ;

    $self -> {accept_unicode} = $flags1 & 0x01;

    if ($debug)
        {
        my @flag1str;
        foreach my $i ( sort keys %msgflags1 ) 
            {
            push @flag1str, $msgflags1{ $i } if $flags1 & $i;
            }
        my $flag1str = join( ",", @flag1str );

        my @flag2str;
        foreach my $i ( sort keys %msgflags2 ) 
            {
            push @flag2str, $msgflags2{ $i } if $flags2 & $i;
            }
            my $flag2str = join( ",", @flag2str );
    
        print STDERR "AuthenNTLM: protocol=$protocol, type=$type, flags1=$flags1($flag1str), flags2=$flags2($flag2str), domain length=$dom_len, domain offset=$dom_off, host length=$host_len, host offset=$host_off, host=$host, domain=$domain\n" ;
        }


    return $type ;
    }


sub set_msg2

    {
    my ($self, $r, $nonce) = @_ ;

    my $charencoding = $self->{ accept_unicode } ? $invflags1{ NEGOTIATE_UNICODE } : $invflags1{ NEGOTIATE_OEM };

    my $flags2 = $invflags2{ NEGOTIATE_ALWAYS_SIGN } | $invflags2{ NEGOTIATE_NTLM };

    my $data = pack ('Z8Ca7vvCCa2a8a8', 'NTLMSSP', 2, '', 40, 0, $charencoding,  $flags2, '', $nonce, '') ;

    my $header = 'NTLM '. MIME::Base64::encode($data, '') ;
    $r->err_header_out ($r->proxyreq ? 'Proxy-Authenticate' : 'WWW-Authenticate', $header) ;
   
    if ($debug)
        {
        print STDERR "AuthenNTLM: Send: " ;
        for (my $i = 0; $i < length($data); $i++)
            {
            printf STDERR "%x ", unpack('C', substr($data, $i, 1)) ;
            }
        print STDERR "\n" ;
        print STDERR "AuthenNTLM: charencoding = $charencoding\n";
        print STDERR "AuthenNTLM: flags2 = $flags2\n";
        print STDERR "AuthenNTLM: nonce=$nonce\n" if $debug > 1;
        print STDERR "AuthenNTLM: Send header: $header\n" ;
        }

    }


sub get_msg3

    {
    my ($self, $r, $data) = @_ ;

    my ($protocol, $type, $zero, 
        $lm_len,  $l1, $lm_off,
        $nt_len,   $l3, $nt_off,
        $dom_len, $x1, $dom_off,
        $user_len, $x3, $user_off,
        $host_len, $x5, $host_off,
        $msg_len
        ) = unpack ('Z8Ca3vvVvvVvvVvvVvvVv', $data) ;
    
    my $lm     = $lm_off  ?substr ($data, $lm_off,   $lm_len):'' ;
    my $nt     = $nt_off  ?substr ($data, $nt_off,   $nt_len):'' ;
    my $user   = $user_off? ($self->{accept_unicode} ? substr_unicode ($data, $user_off, $user_len) : substr( $data, $user_off, $user_len ) ) :'' ;
    my $host   = $host_off? ($self->{accept_unicode} ? substr_unicode ($data, $host_off, $host_len) : substr( $data, $host_off, $host_len ) ) :'' ;
    my $domain = $dom_off ? ($self->{accept_unicode} ? substr_unicode ($data, $dom_off,  $dom_len) : substr( $data, $dom_off, $dom_len ) ) :'' ;

    $self -> {userdomain} = $dom_len?$domain:$self -> {defaultdomain} ;
    $self -> {username}   = $user ;
    $self -> {usernthash} = $nt_len ? $nt : $lm;

    if ($debug)
        {
        print STDERR "AuthenNTLM: protocol=$protocol, type=$type, user=$user, host=$host, domain=$domain, msg_len=$msg_len\n" ;
        }


    return $type ;
    }

sub get_basic

    {
    my ($self, $r, $data) = @_ ;

    ($self -> {username}, $self -> {password}) = split (/:/, $data)  ;

    my ($domain, $username) = split (/\\|\//, $self -> {username}) ;
    if ($username)
	{
	$self -> {domain} = $domain ;
	$self -> {username} = $username ;
	}
    else
	{
	$self -> {domain} = $self -> {defaultdomain} ;
	}

    $self -> {userdomain} = $self -> {domain} ; 

    if ($debug)
        {
        print STDERR "AuthenNTLM: basic auth username = $self->{domain}\\$self->{username}\n" ;
        }

    return -1 ;
    }


sub DESTROY

    {
    my ($self) = @_ ;

    Authen::Smb::Valid_User_Disconnect ($self -> {smbhandle}) if ($self -> {smbhandle}) ;
    }



sub handler ($$)
    {
    my ($class, $r) = @_ ;
    my $type ;
    my $nonce = '' ;
    my $self ;
    my $conn = $r -> connection ;

    my $fh = select (STDERR) ;
    $| = 1 ;
    select ($fh) ;

    print STDERR "AuthenNTLM: Start NTLM Authen handler pid = $$, connection = $$conn cuser = ", $conn -> user, ' ip = ', $conn -> remote_ip, ' remote_host = <', $conn -> remote_host, ">\n" if ($debug) ; 
    
    # we cannot attach our object to the connection record. Since in
    # Apache 1.3 there is only one connection at a time per process
    # we can cache our object and check if the connection has changed.
    # The check is done by slightly changing the remote_host member, which 
    # persists as long as the connection does
    # This has to be reworked to work with Apache 2.0
    if (ref ($cache) ne $class || $$conn != $cache -> {connectionid} || $conn -> remote_host ne $cache->{remote_host})
        {
	$conn -> remote_host ($conn -> remote_host . ' ') ;
        $self = {connectionid => $$conn, remote_host => $conn -> remote_host} ;
        bless $self, $class ;
	$cache = $self ;
	print STDERR "AuthenNTLM: Setup new object\n" if ($debug) ; 
        }
    else
        {
        $self = $cache ;
	print STDERR "AuthenNTLM: Object exists user = $self->{userdomain}\\$self->{username}\n" if ($debug) ; 
	
	if ($self -> {ok})
            {
            $conn -> user($self->{mappedusername}) ;

            # we accecpt the user because we are on the same connection
            print STDERR "AuthenNTLM: OK because same connection pid = $$, connection = $$conn cuser = ", $conn -> user, ' ip = ', $conn -> remote_ip, "\n" if ($debug) ; 
            return OK ;
            }
        }

    $self -> get_config ($r) ;


    if (!($type = $self -> get_msg ($r)))
        {
        $r->log_reason('Bad/Missing NTLM/Basic Authorization Header for ' . $r->uri) ;
        
	my $hdr = $r -> err_headers_out ;
        $hdr -> add ($r->proxyreq ? 'Proxy-Authenticate' : 'WWW-Authenticate', 'NTLM') if ($self -> {authntlm}) ;
        $hdr -> add ($r->proxyreq ? 'Proxy-Authenticate' : 'WWW-Authenticate', 'Basic realm="' . $self -> {authname} . '"') if ($self -> {authntlm}) ;
        return AUTH_REQUIRED ;
        }

    if ($type == 1)
        {
        my $nonce = $self -> get_nonce ($r) ;
        if (!$nonce) 
            {
            $r->log_reason("Cannot get nonce for " . $r->uri) ;
            return SERVER_ERROR ;
            }

        $self -> set_msg2 ($r, $nonce) ;
        return AUTH_REQUIRED ;
        }
    elsif ($type == 3)
        {
        if ( !$self->verify_user( $r ) ) 
            {
            if ( $self->{ntlmauthoritative} ) 
                {
                my $hdr = $r -> err_headers_out ;
                $hdr -> add ($r->proxyreq ? 'Proxy-Authenticate' : 'WWW-Authenticate', 'NTLM') if ($self -> {authntlm}) ;
                $hdr -> add ($r->proxyreq ? 'Proxy-Authenticate' : 'WWW-Authenticate', 'Basic realm="' . $self -> {authname} . '"') if ($self -> {authntlm}) ;
                return AUTH_REQUIRED ;
                }
            else 
                {
                return DECLINED;
                }
            }
        }
    elsif ($type == -1)
        {
        my $nonce = $self -> get_nonce ($r) ;
        if (!$nonce) 
            {
            $r->log_reason("Cannot get nonce for " . $r->uri) ;
            return SERVER_ERROR ;
            }
        return $self -> {basicauthoritative}?AUTH_REQUIRED:DECLINED if (!$self -> verify_user ($r)) ;
        }
    else
        {
        $r->log_reason("Bad NTLM Authorization Header type $type for " . $r->uri) ;
        return AUTH_REQUIRED ;
        }

    $conn -> user($self -> {mappedusername} = $self -> map_user ($r)) ;

    $self->{ok} = 1 ;

    print STDERR "AuthenNTLM: OK pid = $$, connection = $$conn cuser = ", $conn -> user, ' ip = ', $conn -> remote_ip, "\n" if ($debug) ; 

    return OK ;
    }


1 ;

__END__

=head1 NAME

Apache::AuthenNTLM - Perform Microsoft NTLM and Basic User Authentication

=head1 SYNOPSIS

	<Location />
	PerlAuthenHandler Apache::AuthenNTLM 
	AuthType ntlm,basic
	AuthName test
	require valid-user

	#                    domain  pdc      bdc
	PerlAddVar ntdomain "MOND    wingr1        "
	PerlAddVar ntdomain "ecos    wingr1   venus"

	PerlSetVar defaultdomain wingr1
	PerlSetVar ntlmdebug 1
	</Location>

=head1 DESCRIPTION

The purpose of this module is to perform a user authentication via Mircosofts
NTLM protocol. This protocol is supported by all versions of the Internet
Explorer and is mainly usefull for intranets. Depending on your preferences
setting IE will supply your windows logon credentials to the web server
when the server asks for NTLM authentication. This saves the user to type in
his/her password again.

The NTLM protocol performs a challenge/response to exchange a random number
(nonce) and get back a md4 hash, which is build form the users password
and the nonce. This makes sure that no cleartext password goes over the wire.

The main advantage of the Perl implementaion is, that it can be easily extented
to verfiy the user/password against other sources than a windows domain controller.
The default implementaion is to go to the domain controller for the given domain 
and verify the user. If you want to verify the user against another source, you
can inherit from Apache::AuthenNTLM and override it's methods.

To support users that aren't using Internet Explorer, Apache::AuthenNTLM can
also perform basic authentication depending on it's configuration.

B<IMPORTANT:> NTLM authentification works only when KeepAlive is on. 


=head1 CONFIGURATION


=head2 AuthType 

Set the type of authentication. Can be either "basic", "ntlm"
or "ntlm,basic" for doing both.
 
=head2 AuthName

Set the realm for basic authetication

=head2 require valid-user

Necessary to tell Apache to require user authetication at all. Can also 
used to allow only some users, e.g.

  require user foo bar

Note that Apache::AuthenNTLM does not perform any authorization, it 
the require xxx is executed by Apache itself. Alternativly you can
use another (Perl-)module to perform authorization.


=head2 PerlAddVar ntdomain "domain pdc bdc"

This is used to create a maping between a domain and a pdc and bdc for
that domain. Domain, pdc and bdc must be space separated. You can
specify mappings for more than one domain.


=head2 PerlSetVar defaultdomain 

Set the default domain. This is used when the client does not provide
any information about the domain.

=head2 PerlSetVar ntlmauthoritative

Setting the ntlmauthoritative directive explicitly to 'off' allows authentication
to be passed on to lower level modules if AuthenNTLM cannot autheticate the user
and the NTLM authentication scheme is used.
If set to 'on', which is the default, AuthenNTLM will try to verify the user and
if it fails will give an Authorization Required reply. 

=head2 PerlSetVar basicauthoritative

Setting the ntlmauthoritative directive explicitly to 'off' allows authentication
to be passed on to lower level modules if AuthenNTLM cannot autheticate the user
and the Basic authentication scheme is used.
If set to 'on', which is the default, AuthenNTLM will try to verify the user and
if it fails will give an Authorization Required reply. 

=head2 PerlSetVar ntlmdebug 

Set this to 1 if you want extra debugging information in the error log


=head1 OVERRIDEABLE METHODS

Each of the following methods gets the Apache object as argument. Information
about the current authetication can be found inside the object Apache::AuthenNTLM 
itself. To override then methods, create our own class which inherits from
Apache::AuthenNTLM and use it in httpd.conf e.g. 	

	PerlAuthenHandler Apache::MyAuthenNTLM 


=head2 $self -> get_config ($r)

Will be called after the object is setup to read in configuration informations.
The $r -> dir_config can be used for that purpose.

=head2 $self -> get_nonce ($r)

Will be called to setup the connection to the windows domain controller 
for $self -> {domain} and retrieve the nonce.
In case you do not autheticate against a windows machine, you simply need 
to set $self -> {nonce} to a 8 byte random string. Returns undef on error.

=head2 $self -> verify_user ($r)

Should verify that the given user supplied the right credentials. Input:

=over

=item $self -> {basic}

Set when we are doing basic authentication

=item $self -> {ntlm}

Set when we are doing ntlm authentication

=item $self -> {username}

The username

=item $self -> {password}

The password when doing basic authentication

=item $self -> {usernthash}

The md4 hash when doing ntlm authentication

=item $self -> {userdomain}

The domain

=back

returns true if this is a valid user.

=head2 $self -> map_user ($r)

Is called before to get the user name which should be available as REMOTE_USER
to the request. Default is to return DOMAIN\USERNAME.

=head2 Example for overriding

The following code shows the a basic example for createing a module which
overrides the map_user method and calls AuthenNTLM's handler only if a
precondition is met. Note: The functions preconditon_met and lookup_user
do the real work and not shown here.


    package Apache::MyAuthenNTLM ;

    use Apache::AuthenNTLM ;

    @ISA = ('Apache::AuthenNTLM') ;


    sub handler ($$)
        {
        my ($self, $r) = @_ ;

        return Apache::AuthenNTLM::handler ($self, $r) if (precondition_met()) ;
        return DECLINED ;
        }

    sub map_user

        {
        my ($self, $r) = @_ ;

        return lookup_user ($self->{userdomain}, $self->{username}) ;
        }


=head1 AUTHOR

G. Richter (richter@dev.ecos.de)
