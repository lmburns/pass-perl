#!/usr/bin/env perl

############################################################################
#    Author: Lucas Burns                                                   #
#     Email: burnsac@me.com                                                #
#   Created: 2021-05-10 11:04                                              #
############################################################################

use strict;
use warnings;
use feature qw(say);
use experimental qw(switch);

use Data::Dumper qw(Dumper);

# use Readonly;
# use IO::Null;
# use IO::Handle;
# use GnuPG::Interface;
use MIME::Base64;

# use Scalar::MoreUtils qw( define empty );

use POSIX;
use Cwd qw(cwd abs_path getcwd);
use File::Basename qw(basename dirname);
use File::Copy qw(move);
use File::Find;
use File::Path qw(make_path);
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

sub cdie { die RED "Error: ", RESET @_, "\n"; };

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

# my $PREFIX           = $ENV{'PASSWORD_STORE_DIR'} // "$ENV{HOME}/.password-store";
my $PREFIX = "/Users/lucasburns/mybin/perl/testgit";
my $EXTENSIONS       = $ENV{'PASSWORD_STORE_EXTENSIONS_DIR'} // "$PREFIX/.password-store";
my $X_SELECTION      = $ENV{'PASSWORD_STORE_X_SELECTION'}      // "clipboard";
my $CLIP_TIME        = $ENV{'PASSWORD_STORE_CLIP_TIME'}        // 45;
my $GENERATED_LENGTH = $ENV{'PASSWORD_STORE_GENERATED_LENGTH'} // 25;
my $CHARACTER_SET    = $ENV{'PASSWORD_STORE_CHARACTER_SET:'}   // '[:graph:]';
my $CHARACTER_SET_NO_SYMBOLS = $ENV{'PASSWORD_STORE_CHARACTER_SET_NO_SYMBOLS:'} // '[:alnum:]';

$ENV{'GIT_CEILING_DIRECTORIES'} = "$PREFIX/..";

#
# === HELPER FUNCTIONS === {{{
#

my $INNER_GIT_DIR;

# set_git {{{
sub set_git {
 # FIX: get user input
 # FIX: add glob?
 # $xy =~ /$xx=~s|\/$||r*/) --- @{[ $tt=~s|/$||r ]} -- @{[ $PREFIX=~s|/$||r ]}*"
    $INNER_GIT_DIR = dirname(@_);
    while ( !-d $INNER_GIT_DIR && dirname($INNER_GIT_DIR) =~ /$PREFIX=~s|\/$||r*/ ) {
        $INNER_GIT_DIR = dirname($INNER_GIT_DIR);
        chomp( my $tmp = `git -C $INNER_GIT_DIR rev-parse --is-inside-work-tree 2>/dev/null` );
        $tmp eq "true"
          ? $INNER_GIT_DIR = Git::Repository->new( work_tree => $INNER_GIT_DIR )
          : ( $INNER_GIT_DIR = '' );
    }
}
# }}} set_git

# git_add_file {{{
sub git_add_file {
    $INNER_GIT_DIR ne "" || return;
    $INNER_GIT_DIR->run( add    => $_[0] )                || return;
    $INNER_GIT_DIR->run( status => '--porcelain', $_[0] ) || return;
    git_commit( @_[1..$#_] );
}
# }}} git_add_file

# git_commit {{{
sub git_commit {
    my $sign = "";
    $INNER_GIT_DIR ne "" || return;
    my $tmpo =
      $INNER_GIT_DIR->run( config => '--bool', '--get', 'pass.signcommits' );
    $tmpo eq 'true' && ( $sign = '-S' );
    $INNER_GIT_DIR->run( commit => $sign, '-m', $_[0] );
}
# }}} git_commit

# yesno {{{
sub yesno {
    say "[y/N]?";

    # FIX: make exit status // -t STDIN
    -t 0 && chomp( my $ans = <STDIN> );
    cdie("Exiting: $!") unless $ans =~ /[Yy](es)?/;
}
# }}} yesno

# verify_file {{{
sub verify_file {
    defined $ENV{'PASSWORD_STORE_SIGNING_KEY'} || return 0;
    ( -f "$_[0].sig" ) || cdie("Signature for $_[0] doesn't exist");
    my @s;

    # FIX: password-store opts array
    @s = defined $ENV{'PASSWORD_STORE_GPG_OPTS'} ? $ENV{'PASSWORD_STORE_GPG_OPTS'} : ();
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
    $found == 1 || cdie("Signature for $_[0] is invalid");
}
# }}} verify_file

my @GPG_RECIPIENT_ARGS = ();
my @GPG_RECIPIENTS     = ();
my $gpg_id;

# set_gpg_recipients {{{
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
  open( my $fh, '<', $current ) or cdie("Couldn't open '$current' $!");
  while ( my $gpg_id = <$fh> ) {
    chomp($gpg_id);
    push @GPG_RECIPIENT_ARGS, ( "-r", "$gpg_id" );
    push @GPG_RECIPIENTS, "$gpg_id";
  }
  close $fh;
}
# }}} set_gpg_recipients

# reencrypt_path {{{
sub reencrypt_path {
  my ( $prev_gpg_recipients, $gpg_keys, $current_keys, @passfiles ) = ( "", (), "", ());
  my ( $index,               $passfile, @s );
  @s = defined $ENV{'PASSWORD_STORE_GPG_OPTS'} ? $ENV{'PASSWORD_STORE_GPG_OPTS'} : ();

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
# }}} reencrypt_path

# check_sneaky_paths {{{
sub check_sneaky_paths {
  for my $path (@_) {
    $path =~ m!(/\.{2}$)|(^\.{2}/)|(\.{2}/)|(^\.{2}$)!
      && cdie("Sneaky path was passed: $_");
  }
}
# }}} check_sneaky_paths

#
# }}} === END helper functions ===
#

#
# === BEGIN platform definable === {{{
#

# FIX: WHOLE FUNCTION
# clip {{{
sub clip {
  my $sleep_argv0 = "password store sleep for user $<";
  # use File::Spec;
  # System::Command
  # open STDOUT, '>', File::Spec->devnull() || die "$!\n"; {
  # kill 'KILL', @{ find_proc(name=>qr{^$sleep_argv0}) } && sleep 0.5;
  system('pkill', '-f', "^$sleep_argv0", '2>/dev/null') && sleep 0.5;
  my $before = encode_base64(pbpaste());
  pbcopy("$_[0]");
  # FIX: disown, setsid
  local $SIG{HUP} = 'IGNORE';
  { exec("$sleep_argv0") }; sleep "$CLIP_TIME";
  my $now = encode_base64(pbpaste());
  "$now" ne encode_base64("$_[0]") && ( $before = $now );
  pbcopy(decode_base64($before));
  # >/dev/null & disown
  say "Copied $_[1] to the clipboard. Will clear in $CLIP_TIME seconds."
}
# }}} clip

use Proc::Background;
sub c2 {
  my $sleep_argv0 = "password store sleep for user $<";
  system("pkill -f $sleep_argv0 2>/dev/null") && sleep 0.5;
  my $before = encode_base64(pbpaste());
  pbcopy("$_[0]");
  # system("exec -a $sleep_argv0 sleep $CLIP_TIME");
  # $0 = "$sleep_argv0"; pause;
  # timeout_system($CLIP_TIME, $sleep_argv0);
  my $pid = fork();
  die "unable to fork: $!" unless defined($pid);
  if (!$pid) {  # child
    setpgrp(0, 0);
    # exec("leep 2");
    $0 = "$sleep_argv0"; pause;
    # exec("sleep $CLIP_TIME");
    die "unable to exec: $!";
  }
  waitpid $pid, 0;
}

# clip help {{{
#######################
# pkill -f "^$sleep_argv0" 2>/dev/null && sleep 0.5
# local before="$(pbpaste | $BASE64)"
# echo -n "$1" | pbcopy
# (
#   ( exec -a "$sleep_argv0" sleep "$CLIP_TIME" )
#   local now="$(pbpaste | $BASE64)"
#   [[ $now != $(echo -n "$1" | $BASE64) ]] && before="$now"
#   echo "$before" | $BASE64 -d | pbcopy
# ) >/dev/null 2>&1 & disown
# echo "Copied $2 to clipboard. Will clear in $CLIP_TIME seconds."
#######################
# my ($now, $decode_tmp);
# my $cmd = 'system("exec -a $sleep_argv0 sleep $CLIP_TIME");
# $now = encode_base64(pbpaste());
# $before = $now if ($now ne encode_base64(pbpaste()));
# $decode_tmp = decode_base64(pbpaste());
# pbcopy($decode_tmp);';
# my $proc1 = Proc::Background->new("$cmd");
#######################
# unless ($$ = fork) {
# die "cannot fork child: $!";
# unless (fork) {
#   exec "$sleep_argv0 sleep $CLIP_TIME";
#   die "exec failed!";
# }
# exit 0;
# }
# waitpid($$, 0);
#######################
# my $pid = fork();
# die "unable to fork: $!" unless defined($pid);
# if (!$pid) {  # child
# setpgrp(0, 0);
# exec("sleep 2");
# die "unable to exec: $!";
# }
#######################
# $show_cmd && print "% $cmd\n" ;
# system $cmd or die "exec() failed: $!\n" ;
# printf "Session end pid to kill %d\n", $pid;
# kill 9, -$pid;
# waitpid $pid, 0;
# printf "End of the script.\n";
#######################
  # local $SIG{CHLD} = 'IGNORE';
# if(!defined($$ = fork())) {
#   die "Cannot fork a child: $!";
# } elsif ($$ == 0) {
#   print "Printed by child process\n";
#   exec("date") || die "can't exec date: $!";
# } else {
#   print "Printed by parent process\n";
#   my $ret = waitpid($$, 0);
#   print "Completed process id: $ret\n";
# }
# 1;
# say $$;
#######################
# say "PID $$";
# my $pid = fork();
# die if not defined $pid;
# say "PID $$ ($pid)";
#######################
# }}} clip help

# qrcode {{{
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
# }}} qrcode

# my $GETOPT = qx(brew --prefix gnu-getopt 2>/dev/null || { which port &>/dev/null && echo /opt/local; } || echo /usr/local/bin/getopt);
my $SHRED = qx(brew --prefix coreutils &>/dev/null && echo "\$(brew --prefix coreutils)/libexec/gnubin/shred" || { which gshred &>/dev/null && echo /usr/local/bin/gshred; } || echo /usr/local/bin/shred );
# my $BASE64 = qx{openssl base64};

use File::Temp qw{tempfile :mktemp};
# use sigtrap qw(handler unmount_tmpdir INT TERM EXIT);

# use Sys::Filesystem ();
# my @filesystems = Sys::Filesystem->filesystems();

# tmpdir {{{
sub tmpdir {
  my $tdir = $ENV{'TMPDIR'} // '/tmp';
  my $SECURE_TMPDIR = File::Temp->newdir("$tdir/$prog.XXXXXX");
  my $DARWIN_RAMDISK_DEV = qx{hdid -drivekey system-image=yes -nomount 'ram://32768' | cut -d ' ' -f 1};
  return if $SECURE_TMPDIR eq "";
  local *unmount_tmpdir = sub {
    ($SECURE_TMPDIR ne "" && -d $SECURE_TMPDIR && $DARWIN_RAMDISK_DEV ne "") || return;
    system("umount $SECURE_TMPDIR");
    system("disutil quiet eject $DARWIN_RAMDISK_DEV");
    unlink($SECURE_TMPDIR) or cdie("Couldn't delete $SECURE_TMPDIR");
  };
  local $SIG{INT} = \&unmount_tmpdir;
  local $SIG{TERM} = \&unmount_tmpdir;
  local $SIG{EXIT} = \&unmount_tmpdir;
  die RED "Error: ", RESET " could not create ramdisk\n" if $DARWIN_RAMDISK_DEV eq "";
  system("newfs_hfs -M 700 $DARWIN_RAMDISK_DEV &>/dev/null") || cdie("could not create FS on ramdisk");
  system("mount -t hfs -o noatime -o nobrowse $DARWIN_RAMDISK_DEV $SECURE_TMPDIR") || cdie("could not mount FS on ramdisk");
}
# }}} tmpdir

# local *prnt = sub {
#   say colored("=" x screen_len($_[0]) . " $_[0] " . "=" x screen_len($_[0]), "bold $_[1]");
# };

#
# }}} === END Platform Specific
#

# version {{{
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
# }}} version

# cmd_init {{{
sub cmd_init {
  my ($id_path, $id_print, %opts, $command);
  # GetOptions("path|p=s" => \my $opts);
  my @init_opts = ("help|h+", "path|p=s");
  GetOptions(\%opts => @init_opts);
  foreach (keys(%opts)) {
    # TIP: can only use when if no var name supplied
    when(/p|path/) { $id_path = $opts{'path'} }
  };
  # use this in case this sub is called with no args
  $command = defined($ARGV[0]) ? $ARGV[0] : '';
  cdie(GREEN "Usage: ", RESET "$prog $command [{--path,-p} subfolder] gpg-id") if ((0 == keys (%opts)) || $opts{'help'});
  check_sneaky_paths("$id_path") if $id_path ne "";
  cdie(GREEN "$PREFIX/$id_path ", RESET "exists but is not a directory") if ( $id_path ne "" && !-d "$PREFIX/$id_path" && -e _ );

  # my $gpg_id = "$PREFIX/$id_path/.gpg_id";
  # set_git("$gpg_id");
  # CHECK: argv[0]
  if (scalar(@ARGV) == 1 && $ARGV[1] eq ''){
    cdie(GREEN "$gpg_id", RESET "does not exist, therefore can't be removed") if (! -f $gpg_id);
    unlink($gpg_id) || exit 1;
    if ($INNER_GIT_DIR ne ""){
      # FIX: will this work?
      $INNER_GIT_DIR->run( rm => '-qr', $gpg_id );
      # ${id_path:+ ($id_path)}
      $id_path ||= $id_path;
      # perl seems to have this feature: ${id_path:+id_path}
      git_commit("Deinitialize ${gpg_id}@{[$id_path =~ s/.*/($&)/r]}");
    };
    rmdir(dirname ($gpg_id));
  } else {
    # mkdir("$PREFIX/$id_path") || $!{EEXIST};
    make_path("$PREFIX/$id_path");
    $gpg_id = sprintf "%s\n", @_;
    $id_print = sprintf "%s", @_;
    say "PasswordStore initialized: @{[$id_print =~ s{(.*),}{$1}r]}@{[$id_path =~ s{.*}{($&)}r]}";
    git_add_file($gpg_id,
      "Set GPGid to @{[$id_print =~ s{(.*),}{$1}r]}@{[$id_path =~ s{.*}{($&)}r]}");
    if (ENV{'PASSWORD_STORE_SIGNING_KEY'} ne ""){
      my @signing_keys = ();
      my $key;
      for $key (ENV{'PASSWORD_STORE_SIGNING_KEY'}){
        push(@signing_keys, '--default-signing-key', $key);
      }
      system("$GPG @GPG_OPTS @signing_keys --detach-sign $gpg_id") ||
        cdie("Could not sign", GREEN "$gpg_id");
      $key = qx($GPG --verify --status-fd=1 $gpg_id.sig 2>/dev/null);
      $key =~ /^\[GNUPG:\]\hVALIDSIG\h[\dA-F]{40}.*([\dA-F]{40})/m;
      $key = $1;
      cdie "Signing of .gpg_id unsuccessful" unless ($key ne "");
      git_add_file("${gpg_id}.sig", "Signing new GPG id with @{[$key =~ s/\s/,/g]}");
    }
  }
  reencrypt_path("$PREFIX/$id_path");
  git_add_file("$PREFIX/$id_path", "Reencrypt password-store using new GPG id @{[$id_print =~ s/(.*),/$1/r]}@{[$id_path =~ s/.*/$&/r]}");
}
# }}} cmd_init

# cmd_show {{{
sub cmd_show {
  my (%opts, $selected_line, $command);
  my ($clip, $qrcode) = (0, 0);
  my @show_opts = ("clip|c=i", "qrcode|q=i");
  GetOptions(\%opts => @show_opts);
  foreach (keys(%opts)) {
    when(/q|qrcode/) { $selected_line = $opts{'qrcode'} // 1 };
    when(/c|clip/)   { $selected_line = $opts{'clip'} // 1 };
  }
  say $ARGV[0];
  say $ARGV[1];
  say $selected_line;
  # while (my ($k,$v)=each %opts){print "$k $v\n"};
  $command = defined($ARGV[0]) ? $ARGV[0] : '';
  cdie(GREEN "Usage: ", RESET "$prog $command [{--clip,-c} line-number] [{--qrcode,-q} line-number] [pass-name]") if ( $? != 0 || ($opts{'qrcode'} && $opts{'clip'}) );
  my $pass;
  my $path = "$ARGV[1]";
  my $passfile = "$PREFIX/$path.gpg";
  check_sneaky_paths("$path");
  if (-f $passfile) {
    # DISCOVER: why doesn't unless work here?
    if (!$opts{'clip'} && !$opts{'qrcode'}) {
      $pass = qx{$GPG -d @GPG_OPTS $passfile} || cdie("Couldn't decrypt $!");
      $pass = encode_base64($pass);
      say decode_base64($pass);
      say 'here';
    } else {
      cdie("Clip location $selected_line is not a number") unless ($selected_line =~ /^\d+$/);
      $pass = qx{$GPG -d @GPG_OPTS $passfile | tail -n +$selected_line | head -n 1};
      cdie("There is no password to put on clipboard at $selected_line") if ($pass eq "");
      if ($opts{'clip'}) {
        clip($pass, $path);
      } elsif ($opts{'qrcode'}) {
        qrcode($pass, $path);
      }
    }
  } elsif (-d "$PREFIX/$path") {
    if ($path eq "") {
      say "Password Store";
    } else {
      say "@{[$path =~ s{(.*)/}{$1}r]}"
    }
    my $tmp_out = qx("tree -C -l --noreport $PREFIX/$path | tail -n +2");
    # sed -E 's/\.gpg(\x1B\[[0-9]+m)?( ->|$)/\1\2/g'
  } elsif ($path eq "") {
    cdie("passord store is empty. Try 'pass init'");
  } else {
    cdie("$path is not in the password store");
  }
}
# }}} cmd_show

# exec("pod2usage $0") if ((0 == keys (%opts)) || $opts{'help'});
# while (my ($k,$v)=each %opts){print "$k $v\n"};


__DATA__

=head1 NAME

  pass-perl.pl

=head1 DESCRIPTION

  An implementation of the password-manager 'pass' in Perl.

=head1 SYNOPSIS

  pass-perl -h

  [-help -h]      Print out usage information

=cut

# vim:ft=perl:et:sw=0:ts=2:sts=2:fdm=marker:fmr={{{,}}}:
