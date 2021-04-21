#!/usr/bin/env perl

use strict;
use warnings;
use feature 'say';

use Readonly;
use Cwd              qw(cwd abs_path);
use File::Basename   qw(basename dirname);

use Getopt::Long     qw(GetOptions);
use Pod::Usage       qw(pod2usage);
use Git::Repository;
# use Crypt::Random    qw(makerandom);

# use Git;
# PerlX::bash

BEGIN {
  select(STDERR);
  $| = 1;
  select(STDOUT);
  $| = 1;
}

my $prog = basename $0;
# umask $ENV{'PASSWORD_STORE_UMASK'} // 077;

my @GPG_OPTS=( $ENV{'PASSWORD_STORE_GPG_OPTS'} // '',
  "--quiet", "--yes", "--compress-algo=none", "--no-encrypt-to" );
my $GPG = "gpg";
$ENV{'GPG_TTY'} = $ENV{'GPG_TTY'} // "$ENV{tty}";
unless(system('which gpg2 >/dev/null')){ $GPG = 'gpg2' };
if(defined $ENV{'GPG_AGENT_INFO'} || $GPG eq "gpg2"){ push(@GPG_OPTS, '--batch', '--use-agent') };

my $PREFIX = $ENV{'PASSWORD_STORE_DIR'} // "$ENV{HOME}/.password-store";
my $EXTENSIONS = $ENV{'PASSWORD_STORE_EXTENSIONS_DIR'} // "$PREFIX/.password-store";
my $X_SELECTION = $ENV{'PASSWORD_STORE_X_SELECTION'} // "clipboard";
my $CLIP_TIME = $ENV{'PASSWORD_STORE_CLIP_TIME'} // 45;
my $GENERATED_LENGTH = $ENV{'PASSWORD_STORE_GENERATED_LENGTH'} // 25;
my $CHARACTER_SET = $ENV{'PASSWORD_STORE_CHARACTER_SET:'} // '[:graph:]';
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
  while (! -d $INNER_GIT_DIR && dirname($INNER_GIT_DIR) =~ /$PREFIX=~s|\/$||r*/ ) {
    $INNER_GIT_DIR = dirname($INNER_GIT_DIR);
  chomp(my $tmp = `git -C $INNER_GIT_DIR rev-parse --is-inside-work-tree 2>/dev/null`);
  $tmp eq "true" ? $INNER_GIT_DIR = Git::Repository->new( work_tree => $INNER_GIT_DIR ) : ($INNER_GIT_DIR = '');
  }
}

sub git_add_file {
  $INNER_GIT_DIR ne "" || return;
  $INNER_GIT_DIR->run( add => $_[0] ) || return;
  $INNER_GIT_DIR->run( status => '--porcelain', $_[0] ) || return;
  git_commit($_[1]);
}

sub git_commit {
  my $sign = "";
  $INNER_GIT_DIR ne "" || return;
  my $tmpo = $INNER_GIT_DIR->run( config => '--bool', '--get', 'pass.signcommits' );
  $tmpo eq 'true' && ( $sign = '-S' );
  $INNER_GIT_DIR->run( commit => $sign, '-m', $_[0] );
}

sub yesno {
  say "[y/N]?";
  # FIX: make exit status // -t STDIN
  -t 0 &&
  chomp (my $ans = <STDIN>);
  die "Exiting: $!\n" unless $ans =~ /[Yy](es)?/
}

sub verify_file {
  defined $ENV{'PASSWORD_STORE_SIGNING_KEY'} || return 0;
  (-f "$_[0].sig") || die "Signature for $_[0] doesn't exist";
  my @s;
  # FIX: password-store opts array
  defined $ENV{'PASSWORD_STORE_GPG_OPTS'} ? @s = $ENV{'PASSWORD_STORE_GPG_OPTS'} : (@s = ());
  my $fingerprints = qx($GPG @s --verify --status-fd=1 "$_[0].sig" "$_[0]" 2>/dev/null);
  $fingerprints =~ /^(?:\[GNUPG:\]\hVALIDSIG\h)\K([\dA-F]{40}).*([\dA-F]{40})$/m;
  $fingerprints = "${1}\n${2}";
  my $found = 0;
  for my $fingerprint (split(/\h+/, $ENV{'TESTGKEY'})) {
    $fingerprint =~ /^[\dA-F]{40}$/gm || next;
    if($fingerprints =~ /.*$fingerprint.*/){$found = 1; last};
  }
  $found == 1 || die "Signature for $_[0] is invalid";
}

my @GPG_RECIPIENT_ARGS = ();
my @GPG_RECIPIENTS = ();
my $gpg_id;

sub set_gpg_recipients {
  if (defined $ENV{'PASSWORD_STORE_SIGNING_KEY'}) {
    for $gpg_id (split(/\h+/, $ENV{'PASSWORD_STORE_SIGNING_KEY'})) {
      push @GPG_RECIPIENT_ARGS, ("-r", "$gpg_id");
      push @GPG_RECIPIENTS, "$gpg_id";
    }
   return
  }

  my $current = "$PREFIX/$_[0]";
  while($current ne $PREFIX && ! -f "$current/.gpg-id") {
    $current = dirname($current);
  }
  $current = "$current/.gpg-id";
  if (! -f $current) {
    pod2usage(  -message => "$prog init your-gpg-id",
                -section => [qw(SYNOPSIS)],
                -output  => \*STDERR,
                -exitval => 1);
  }
  verify_file("$current");
  open(my $fh, '<', $current) or die "Couldn't open '$current' $!";
  while (my $gpg_id = <$fh>) {
    chomp($gpg_id);
    push @GPG_RECIPIENT_ARGS, ("-r", "$gpg_id");
    push @GPG_RECIPIENTS, "$gpg_id";
  }
  close $fh;
}

sub reencrypt_path {
  my ($prev_gpg_recipients, $gpg_keys, $current_keys) = ("", (), "");
  my ($index, $passfile, @s);
  defined $ENV{'PASSWORD_STORE_GPG_OPTS'} ? @s = $ENV{'PASSWORD_STORE_GPG_OPTS'} : (@s = ());
  # my $groups = qx($GPG @s --list-config --with-colons) =~ /^cfg:group:.*/;
  my $groups = qx($GPG @s --list-config --with-colons group);

  # FIX: while read loop here
  my $passfile_dir = dirname($passfile);
  $passfile_dir = basename($passfile_dir);
  my $passfile_display = basename($passfile);
  $passfile_display =~ s/\.gpg//;
  my $passfile_temp = join(".", "${passfile}.tmp", map { int(rand($_)) } (9999) x 4) . ".--";

  set_gpg_recipient("$passfile_dir");
  if ($prev_gpg_recipients ne @GPG_RECIPIENTS) {
    for my $index (0 .. $#GPG_RECIPIENTS) {
      my $r = $GPG_RECIPIENTS[$index] =~ s|[/&]|\\$&|gr;
      # DISCOVER: group has to be email?
      my $group = (split /\n/, $groups)[0] =~ s{^(cfg:group:$r:\K(.*)$)}{$1}gr;

      $group eq "" && next;
      push(@GPG_RECIPIENTS, split /;/, $groups);
      delete $GPG_RECIPIENTS[$index];
    }
    $gpg_keys = qx($GPG @s --list-keys --with-colons @GPG_RECIPIENTS);
    my @gpg_keys = split(/\s/,
      join(" ", $gpg_keys =~ /^sub(?::[^:]*){3}:([^:]*)(?::[^:]*){6}:[[:alpha:]]*e[[:alpha:]]*:.*/mg));
    $gpg_keys = join(" ", do { my %ref; grep { !$ref{$_}++ } @gpg_keys });
    # FIX: locale sort (if needed)
  }
  $current_keys = qx($GPG -v --no-secmem-warning --no-permission-warning --decrypt --list-only --keyid-format long $passfile 2>&1);
  my @current_keys = split(/\s/, join(" ", $current_keys =~ /^gpg: public key is ([\dA-F]+)$/m));
  $current_keys = join(" ", do { my %ref; grep { !$ref{$_}++ } @current_keys });

  if ( $gpg_keys ne $current_keys ) {
    say "$passfile_display: reencrypting to " . $gpg_keys =~ s/\n//rg ;
  };
}

my $gpg_keys = "";
my $passfile = "/Users/lucasburns/mybin/perl/testgit/cou.gpg";
my $pre = "/Users/lucasburns/mybin/perl/testgit";
my $passfile_display = basename($passfile);
$passfile_display =~ s/\.gpg//;
say "$passfile";
my @sa = (9999) x 4;
my $pp = join(".", "${passfile}.tmp", map { int(rand($_)) } (9999) x 4) . ".--";
my $prev_gpg = "";
my @gpg_rec = qw(burnsac@me.com asdf@gmail.com);
my $groups = qx($GPG --list-config --with-colons group);

##
$gpg_keys = qx($GPG --list-keys --with-colons burnsac\@me.com);
my @gpg_keys = split(/\s/,
  join(" ", $gpg_keys =~ /^sub(?::[^:]*){3}:([^:]*)(?::[^:]*){6}:[[:alpha:]]*e[[:alpha:]]*:.*/mg));
$gpg_keys = join(" ", do { my %ref; grep { !$ref{$_}++ } @gpg_keys });

my $current_keys = qx($GPG -v --no-secmem-warning --no-permission-warning --decrypt --list-only --keyid-format long $passfile 2>&1);

my @current_keys = split(/\s/, join(" ", $current_keys =~ /^gpg: public key is ([\dA-F]+)$/m));
$current_keys = join(" ", do { my %ref; grep { !$ref{$_}++} @current_keys });

say $gpg_keys;
say $current_keys;

if ( $gpg_keys ne $current_keys ) {
  say "$passfile_display: reencrypting to " . $gpg_keys =~ s/\n//rg;
  my $f = qx($GPG -d $passfile);
  say $f;
};

###############################################

# 			$GPG -d "${GPG_OPTS[@]}" "$passfile" | $GPG -e "${GPG_RECIPIENT_ARGS[@]}" -o "$passfile_temp" "${GPG_OPTS[@]}" &&
# 			mv "$passfile_temp" "$passfile" || rm -f "$passfile_temp"
# 		fi
# 		prev_gpg_recipients="${GPG_RECIPIENTS[*]}"
# 	done < <(find "$1" -path '*/.git' -prune -o -iname '*.gpg' -print0)
# }
# check_sneaky_paths() {
# 	local path
# 	for path in "$@"; do
# 		[[ $path =~ /\.\.$ || $path =~ ^\.\./ || $path =~ /\.\./ || $path =~ ^\.\.$ ]] && die "Error: You've attempted to pass a sneaky path to pass. Go home."
# 	done
# }


##################################3
# my @gfs = qw(words added);
# my @afs = ();
# my $tpref = '/Users/lucasburns/mybin/perl/testgit';

# sub set_gpg_recipient {
#   my $current = "$tpref/$_[0]";
#   while ($current ne $tpref && ! -f "$current/.gpg-id") {
#     $current = dirname("$current");
#   }
#   $current = "$current/.gpg-id";
#   if (! -f $current) {
#     pod2usage(  -message => "$prog init your-gpg-id before using the password-store",
#                 -section => [qw(SYNOPSIS)],
#                 -output  => \*STDERR,
#                 -exitval => 1);
#   }
#   verify_file("$current");
#   open my $fh, '<', $current or die "Couldn't open '$current' $!";
#   while (my $gpg_id = <$fh>) {
#     chomp($gpg_id);
#     push @GPG_RECIPIENT_ARGS, ("-r", "$gpg_id");
#     push @GPG_RECIPIENTS, "$gpg_id";
#   }
#   close $fh;
#   say "@GPG_RECIPIENT_ARGS";
# }

# set_gpg_recipient('fold1/fold2');
##################################3



## STDIN TTY #############################################
# my $isa_tty = -t STDIN && (-t STDOUT || !(-f STDOUT || -c STDOUT));

# sub is_interactive {
#     my ($out_handle) = (@_, select);    # Default to default output handle

#     # Not interactive if output is not to terminal...
#     return 0 if not -t $out_handle;

#     # If *ARGV is opened, we're interactive if...
#     if ( tied(*ARGV) or defined(fileno(ARGV)) ) { # IO::Interactive::Tiny: this is the only relavent part of Scalar::Util::openhandle() for 'openhandle *ARGV'
#         # ...it's currently opened to the magic '-' file
#         return -t *STDIN if defined $ARGV && $ARGV eq '-';

#         # ...it's at end-of-file and the next file is the magic '-' file
#         return @ARGV>0 && $ARGV[0] eq '-' && -t *STDIN if eof *ARGV;

#         # ...it's directly attached to the terminal
#         return -t *ARGV;
#     }

#     # If *ARGV isn't opened, it will be interactive if *STDIN is attached
#     # to a terminal.
#     else {
#         return -t *STDIN;
#     }
# }


__DATA__

=head1 NAME

  pass-perl.pl

=head1 DESCRIPTION

  An implementation of the password-manager 'pass' in Perl.

=head1 SYNOPSIS

  pass-perl -h

  [-help -h]      Print out usage information

=cut
