#!/usr/bin/env perl

use strict;
use warnings;
use feature 'say';

# use Readonly;
# use IO::Null;
# use IO::Handle;
# use GnuPG::Interface;
# use MIME::Base64;

use Cwd qw(cwd abs_path getcwd);
use File::Basename qw(basename dirname);
use File::Copy qw(move);
use File::Find;
use Proc::Find qw(find_proc proc_exists);
use Term::ANSIColor qw(:constants colored);
use Term::ReadKey;

use Mac::Pasteboard;
use Getopt::Long qw(GetOptions);
use Pod::Usage qw(pod2usage);
use Git::Repository;

BEGIN {
    select(STDERR);
    $| = 1;
    select(STDOUT);
    $| = 1;
}

my $prog = (split /\//, $0)[-1];

# umask $ENV{'PASSWORD_STORE_UMASK'} // 077;

my @GPG_OPTS = (
    $ENV{'PASSWORD_STORE_GPG_OPTS'} // '',
    "--quiet", "--yes", "--compress-algo=none", "--no-encrypt-to"
);
my $GPG = "gpg";
$ENV{'GPG_TTY'} = $ENV{'GPG_TTY'} // "$ENV{tty}";
unless ( system('which gpg2 >/dev/null') ) { $GPG = 'gpg2' }
if     ( defined $ENV{'GPG_AGENT_INFO'} || $GPG eq "gpg2" ) {
    push( @GPG_OPTS, '--batch', '--use-agent' );
}

my $PREFIX           = $ENV{'PASSWORD_STORE_DIR'} // "$ENV{HOME}/.password-store";
my $EXTENSIONS       = $ENV{'PASSWORD_STORE_EXTENSIONS_DIR'} // "$PREFIX/.password-store";
my $X_SELECTION      = $ENV{'PASSWORD_STORE_X_SELECTION'}      // "clipboard";
my $CLIP_TIME        = $ENV{'PASSWORD_STORE_CLIP_TIME'}        // 45;
my $GENERATED_LENGTH = $ENV{'PASSWORD_STORE_GENERATED_LENGTH'} // 25;
my $CHARACTER_SET    = $ENV{'PASSWORD_STORE_CHARACTER_SET:'}   // '[:graph:]';
my $CHARACTER_SET_NO_SYMBOLS = $ENV{'PASSWORD_STORE_CHARACTER_SET_NO_SYMBOLS:'} // '[:alnum:]';

$ENV{'GIT_CEILING_DIRECTORIES'} = "$PREFIX/..";

#
# HELPER FUNCTIONS
#

my $INNER_GIT_DIR;

sub set_git {

 # FIX: get user input
 # FIX: add glob?
 # $xy =~ /$xx=~s|\/$||r*/) --- @{[ $tt=~s|/$||r ]} -- @{[ $PREFIX=~s|/$||r ]}*"
    $INNER_GIT_DIR = dirname(@_);
    while ( !-d $INNER_GIT_DIR && dirname($INNER_GIT_DIR) =~ /$PREFIX=~s|\/$||r*/ ) {
        $INNER_GIT_DIR = dirname($INNER_GIT_DIR);
        chomp( my $tmp =
`git -C $INNER_GIT_DIR rev-parse --is-inside-work-tree 2>/dev/null`
        );
        $tmp eq "true"
          ? $INNER_GIT_DIR = Git::Repository->new( work_tree => $INNER_GIT_DIR )
          : ( $INNER_GIT_DIR = '' );
    }
}

sub git_add_file {
    $INNER_GIT_DIR ne "" || return;
    $INNER_GIT_DIR->run( add    => $_[0] )                || return;
    $INNER_GIT_DIR->run( status => '--porcelain', $_[0] ) || return;
    git_commit( $_[1] );
}

sub git_commit {
    my $sign = "";
    $INNER_GIT_DIR ne "" || return;
    my $tmpo =
      $INNER_GIT_DIR->run( config => '--bool', '--get', 'pass.signcommits' );
    $tmpo eq 'true' && ( $sign = '-S' );
    $INNER_GIT_DIR->run( commit => $sign, '-m', $_[0] );
}

sub yesno {
    say "[y/N]?";

    # FIX: make exit status // -t STDIN
    -t 0 && chomp( my $ans = <STDIN> );
    die "Exiting: $!\n" unless $ans =~ /[Yy](es)?/;
}

sub verify_file {
    defined $ENV{'PASSWORD_STORE_SIGNING_KEY'} || return 0;
    ( -f "$_[0].sig" ) || die "Signature for $_[0] doesn't exist";
    my @s;

    # FIX: password-store opts array
    defined $ENV{'PASSWORD_STORE_GPG_OPTS'}
      ? @s = $ENV{'PASSWORD_STORE_GPG_OPTS'}
      : ( @s = () );
    my $fingerprints =
      qx($GPG @s --verify --status-fd=1 "$_[0].sig" "$_[0]" 2>/dev/null);
    $fingerprints =~
      /^(?:\[GNUPG:\]\hVALIDSIG\h)\K([\dA-F]{40}).*([\dA-F]{40})$/m;
    $fingerprints = "${1}\n${2}";
    my $found = 0;
    for my $fingerprint ( split( /\h+/, $ENV{'TESTGKEY'} ) ) {
        $fingerprint =~ /^[\dA-F]{40}$/gm || next;
        if ( $fingerprints =~ /.*$fingerprint.*/ ) { $found = 1; last }
    }
    $found == 1 || die "Signature for $_[0] is invalid";
}

my @GPG_RECIPIENT_ARGS = ();
my @GPG_RECIPIENTS     = ();
my $gpg_id;

sub set_gpg_recipients {
  if ( defined $ENV{'PASSWORD_STORE_SIGNING_KEY'} ) {
    for $gpg_id ( split( /\h+/, $ENV{'PASSWORD_STORE_SIGNING_KEY'} ) ) {
      push @GPG_RECIPIENT_ARGS, ( "-r", "$gpg_id" );
      push @GPG_RECIPIENTS, "$gpg_id";
    }
  return;
  }

  my $current = "$PREFIX/$_[0]";
  while ( $current ne $PREFIX && !-f "$current/.gpg-id" ) {
    $current = dirname($current);
  }
  $current = "$current/.gpg-id";
  if ( !-f $current ) {
    pod2usage(
      -message => "$prog init your-gpg-id",
      -section => [qw(SYNOPSIS)],
      -output  => \*STDERR,
      -exitval => 1
    );
  }
  verify_file("$current");
  open( my $fh, '<', $current ) or die "Couldn't open '$current' $!";
  while ( my $gpg_id = <$fh> ) {
    chomp($gpg_id);
    push @GPG_RECIPIENT_ARGS, ( "-r", "$gpg_id" );
    push @GPG_RECIPIENTS, "$gpg_id";
  }
  close $fh;
}

sub reencrypt_path {
  my ( $prev_gpg_recipients, $gpg_keys, $current_keys, @passfiles ) = ( "", (), "", ());
  my ( $index,               $passfile, @s );
  defined $ENV{'PASSWORD_STORE_GPG_OPTS'}
    ? @s = $ENV{'PASSWORD_STORE_GPG_OPTS'}
    : ( @s = () );

  # my $groups = qx($GPG @s --list-config --with-colons) =~ /^cfg:group:.*/;
  my $groups = qx($GPG @s --list-config --with-colons group);

  local *wanted = sub {
    $File::Find::prune = 1 if /^.git/;
    push(@passfiles, $File::Find::name) if (-f && /^.*\.gpg\z/);
  };

  find( {wanted => \&wanted}, $_[0] );

  foreach $passfile (@passfiles) {
    my $passfile_dir = (split /\//, $passfile)[-2];
    my $passfile_display = (split /\//, $passfile)[-1];
    $passfile_display =~ s/\.gpg//;
    my $passfile_temp =
      join( ".", "${passfile}.tmp", map { int( rand($_) ) } (9999) x 4 ) . ".--";

    set_gpg_recipients("$passfile_dir");
    if ( $prev_gpg_recipients ne @GPG_RECIPIENTS ) {
        for my $index ( 0 .. $#GPG_RECIPIENTS ) {
          my $r = $GPG_RECIPIENTS[$index] =~ s|[/&]|\\$&|gr;

          # DISCOVER: group has to be email?
          my $group = ( split /\n/, $groups )[0] =~ s{^(cfg:group:$r:\K(.*)$)}{$1}gr;

          $group eq "" && next;
          push( @GPG_RECIPIENTS, split /;/, $groups );
          delete $GPG_RECIPIENTS[$index];
          }
        $gpg_keys = qx($GPG @s --list-keys --with-colons @GPG_RECIPIENTS);
        my @gpg_keys = split(/\s/, join( " ",
          $gpg_keys =~ /^sub(?::[^:]*){3}:([^:]*)(?::[^:]*){6}:[[:alpha:]]*e[[:alpha:]]*:.*/mg) );
        $gpg_keys = join(" ",
          do {
            my %ref;
            grep { !$ref{$_}++ } @gpg_keys;
          }
        );
      }; # FIX: locale sort (if needed)
    $current_keys = qx(LC_ALL=C $GPG -v --no-secmem-warning --no-permission-warning --decrypt --list-only --keyid-format long $passfile 2>&1);
    my @current_keys = split( /\s/,
      join( " ", $current_keys =~ /^gpg: public key is ([\dA-F]+)$/m ) );
    $current_keys = join(" ",
      do {
        my %ref;
        grep { !$ref{$_}++ } @current_keys;
      }
    );

    # FIX: what if setting is set to hide key?
    if ( $gpg_keys ne $current_keys ) {
      say "$passfile_display: reencrypting to " . $gpg_keys =~ s/\n//rg;
      my $f = qx($GPG -d $passfile | $GPG -e @GPG_RECIPIENT_ARGS -o $passfile_temp @GPG_OPTS);
      move( $passfile_temp, $passfile ) || unlink $passfile_temp;
      };
      $prev_gpg_recipients = @GPG_RECIPIENTS;
  };
}

sub check_sneaky_paths {
  for my $path (@_) {
    $path =~ m!(/\.{2}$)|(^\.{2}/)|(\.{2}/)|(^\.{2}$)!
      && die "Error: Sneaky path was passed: $_\n";
  }
}

#
# END helper functions
#

#
# BEGIN platform definable
#

# FIX: WHOLE FUNCTION
sub clip {
  my $sleep_argv0 = "password store sleep for user $<";
  # use File::Spec;
  # open STDOUT, '>', File::Spec->devnull() || die "$!\n"; {
  # kill 'KILL', @{ find_proc(name=>qr{^$sleep_argv0}) } && sleep 0.5;
  system('pkill', '-f', "^$sleep_argv0", '2>/dev/null') && sleep 0.5;
  my $before = encode_base64(pbpaste());
  pbcopy("$_[0]");
  # FIX: disown, setsid
  $SIG{HUP} = 'IGNORE';
  { exec("$sleep_argv0") }; sleep "$CLIP_TIME";
  my $now = encode_base64(pbpaste());
  "$now" ne encode_base64("$_[0]") && ( $before = $now );
  pbcopy(decode_base64($before));
  # >/dev/null & disown
  say "Copied $_[1] to the clipboard. Will clear in $CLIP_TIME seconds."
}

sub qrcode {
  # unless seemed to have to correct return value
  unless (system('which imgcat >/dev/null 2>&1')) {
    system("echo $_[0] | qrencode --size 10 -o - | imgcat"); exit 1;
  };
  unless (system('which gm >/dev/null 2>&1')) {
    system("echo $_[0] | qrencode --size 10 -o - | gm display -title 'pass: $_[1]' -geometry +200+200 -"); exit 1;
  };
  unless (system('which display >/dev/null 2>&1')) {
    system("echo $_[0] | qrencode --size 10 -o - | display -title 'pass: $_[1]' -geometry +200+200 -"); exit 1;
  };
  unless (system('which imgcat >/dev/null 2>&1')) {
    system("echo $_[0] | qrencode --size 10 -o - | imgcat"); exit 1;
  };
}

my $GETOPT = qx(brew --prefix gnu-getopt 2>/dev/null || { which port &>/dev/null && echo /opt/local; } || echo /usr/local/bin/getopt);
my $SHRED = qx(brew --prefix coreutils &>/dev/null && echo "\$(brew --prefix coreutils)/libexec/gnubin/shred" || { which gshred &>/dev/null && echo /usr/local/bin/gshred; } || echo /usr/local/bin/shred );
# my $BASE64 = qx{openssl base64};
# = sub BASE64 { encode_base64($_[0]) };

use File::Temp qw{tempfile :mktemp};
# use sigtrap qw(handler unmount_tmpdir INT TERM EXIT);

# use Sys::Filesystem ();
# my @filesystems = Sys::Filesystem->filesystems();

sub tmpdir {
  my $tdir = $ENV{'TMPDIR'} // '/tmp';
  my $SECURE_TMPDIR = File::Temp->newdir("$tdir/$prog.XXXXXX");
  my $DARWIN_RAMDISK_DEV = qx{hdid -drivekey system-image=yes -nomount 'ram://32768' | cut -d ' ' -f 1};
  return if $SECURE_TMPDIR eq "";
  local *unmount_tmpdir = sub {
    ($SECURE_TMPDIR ne "" && -d $SECURE_TMPDIR && $DARWIN_RAMDISK_DEV ne "") || return;
    system("umount $SECURE_TMPDIR");
    system("disutil quiet eject $DARWIN_RAMDISK_DEV");
    unlink($SECURE_TMPDIR) or die "Couldn't delete $SECURE_TMPDIR\n";
  };
  $SIG{INT} = \&unmount_tmpdir;
  $SIG{TERM} = \&unmount_tmpdir;
  $SIG{EXIT} = \&unmount_tmpdir;
  die "Error: could not create ramdisk" if $DARWIN_RAMDISK_DEV eq "";
  system("newfs_hfs -M 700 $DARWIN_RAMDISK_DEV &>/dev/null") || die "Error: could not create FS on ramdisk\n";
  system("mount -t hfs -o noatime -o nobrowse $DARWIN_RAMDISK_DEV $SECURE_TMPDIR") || die "Error: could not mount FS on ramdisk\n"
}

# local *prnt = sub {
#   say colored("=" x screen_len($_[0]) . " $_[0] " . "=" x screen_len($_[0]), "bold $_[1]");
# };

sub version {
  my ($wchar, $hchar, $wpix, $hpix) = GetTerminalSize();
  local *screen_len = sub { return ($wchar - length($_[0]) - 2)/2 };
  local *prntc = sub {
    say BOLD $_[1], "=" x screen_len($_[0]),
      RESET BOLD $_[2], " $_[0] ",
      RESET BOLD $_[1], "=" x screen_len($_[0]);
  };
  say BOLD BLUE "=" x $wchar;
  prntc("pass.pl - Perl instantiation of pass", BLUE, MAGENTA);
  prntc("v1.0", BLUE, MAGENTA);
  prntc("Lucas Burns", BLUE, GREEN);
  prntc("lucas\@burnsac.xyz", BLUE, GREEN);
  say BOLD BLUE "=" x $wchar;
}


#
##### TESTING AREA ######
#

my $gpg_keys         = "";
my $passfile         = "/Users/lucasburns/mybin/perl/testgit/cou.gpg";
my $pre              = "/Users/lucasburns/mybin/perl/testgit";

my $passfile_display = basename($passfile);
$passfile_display =~ s/\.gpg//;

my @sa = (9999) x 4;
my $pp =
  join( ".", "${passfile}.tmp", map { int( rand($_) ) } (9999) x 4 ) . ".--";
my $prev_gpg = "";
my @gpg_rec  = qw(burnsac@me.com asfg@gmail.com);
my $groups   = qx($GPG --list-config --with-colons group);

##
$gpg_keys = qx($GPG --list-keys --with-colons burnsac\@me.com);
my @gpg_keys = split(
    /\s/,
    join( " ",
        $gpg_keys =~
/^sub(?::[^:]*){3}:([^:]*)(?::[^:]*){6}:[[:alpha:]]*e[[:alpha:]]*:.*/mg
    )
);
$gpg_keys = join(
    " ",
    do {
        my %ref;
        grep { !$ref{$_}++ } @gpg_keys;
    }
);

my $current_keys =
qx($GPG -v --no-secmem-warning --no-permission-warning --decrypt --list-only --keyid-format long $passfile 2>&1);

my @current_keys = split( /\s/,
    join( " ", $current_keys =~ /^gpg: public key is ([\dA-F]+)$/m ) );
$current_keys = join(" ",
    do {
        my %ref;
        grep { !$ref{$_}++ } @current_keys;
    }
);

#######################
# use File::Find qw(find);
# my @file_list;
# find ( sub {
#   return unless -f;
#   return unless /\.g(it|pg)$/;
#   push @file_list, $File::Find::name;
#   }, $pre);

# $/ = "\0"; foreach (@file_list) { say $_ };
#######################
# use Proc::ProcessTable;
# my $pid;
# my $pt = Proc::ProcessTable->new();
# foreach my $proc (@{$pt->table}) {
#   next if $proc->cmndline =~ /^$sleep_argv0/;
#   if ($proc->cmndline =~ /\Q^$sleep_argv0/) {
#     $pid = $proc->pid;
#     last;
#   }
# };


__DATA__

=head1 NAME

  pass-perl.pl

=head1 DESCRIPTION

  An implementation of the password-manager 'pass' in Perl.

=head1 SYNOPSIS

  pass-perl -h

  [-help -h]      Print out usage information

=cut
