#!/usr/bin/env perl

use strict;
use warnings;
use feature 'say';

use Readonly;
use File::Basename;
use Git::Repository;
use Git;
use Getopt::Long;

# PerlX::bash

# BEGIN {
#   select(STDERR);
#   $| = 1;
#   select(STDOUT);
#   $| = 1;
# }

# umask $ENV{'PASSWORD_STORE_UMASK'} // 077;

sub createDir {
  my ($dir,$perm) = @_;
    unless(-d $dir) {
      mkdir $dir,$perm or die "$!";
   }
}

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

my $tgit = '/Users/lucasburns/mybin/perl/testgit';
my $ggit = '/Users/lucasburns/projects/github';

my $INNER_GIT_DIR;

sub set_git {
  # FIX: get user input
  # FIX: add glob
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
  $INNER_GIT_DIR->run( add => $_[0]) || return;
  $INNER_GIT_DIR->run( status => '--porcelain', $_[0] ) || return;
  git_commit($_[1]);
}

sub git_commit {
  my $sign = "";
  $INNER_GIT_DIR ne "" || return;
  my $tmpo = $INNER_GIT_DIR->run( config => '--bool', '--get', 'pass.signcommits');
  $tmpo eq 'true' && ( $sign = '-S' );
  $INNER_GIT_DIR->run( commit => $sign, '-m', $_[0]);
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
  $found == 1 || die "Signture for $_[0] is invalid";
}

# verify_file('/Users/lucasburns/mybin/perl/testgit/test.txt');

###############################################

# verify_file() {
# 	[[ -n $PASSWORD_STORE_SIGNING_KEY ]] || return 0
# 	[[ -f $1.sig ]] || die "Signature for $1 does not exist."
# 	local fingerprints="$($GPG $PASSWORD_STORE_GPG_OPTS --verify --status-fd=1 "$1.sig" "$1" 2>/dev/null
# | sed -n 's/^\[GNUPG:\] VALIDSIG \([A-F0-9]\{40\}\) .* \([A-F0-9]\{40\}\)$/\1\n\2/p')"
# 	local fingerprint found=0
# 	for fingerprint in $PASSWORD_STORE_SIGNING_KEY; do
# 		[[ $fingerprint =~ ^[A-F0-9]{40}$ ]] || continue
# 		[[ $fingerprints == *$fingerprint* ]] && { found=1; break; }
# 	done
# 	[[ $found -eq 1 ]] || die "Signature for $1 is invalid."
# }







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
