#!/usr/bin/perl
# Shared <script> tag parser for tools/verify-vendor.sh and
# tools/update-sri.sh. perl-base only, no CPAN modules.
#
# Usage: script-tags.pl FILE [FILE ...]
#
# For every <script ...> opening tag found (case-insensitively, grammar
# correct so a '>' inside a quoted attribute value does not end the tag,
# and never matching inside an HTML comment), prints one tab-separated line
# to stdout:
#
#   <file>\t<src-trimmed>\t<integrity-or-empty>\t<byte-offset-of-tag-start>\t<raw-tag>
#
# - src-trimmed: the src attribute value with leading/trailing ASCII
#   whitespace stripped (as a browser would trim it), or empty if there is
#   no src attribute.
# - integrity-or-empty: the integrity attribute value verbatim, or empty.
# - byte-offset-of-tag-start: offset of the '<' of the tag, in the
#   ORIGINAL file's bytes (comments are only used to filter out tags that
#   live inside them; offsets are never shifted by that filtering, so a
#   caller can use the offset to locate the exact bytes in the file).
# - raw-tag: the exact matched tag text, with any internal newlines
#   replaced by a single space so one tag is always one output line.
#
# Exits 0 on success, even when zero tags are found anywhere (the caller
# decides whether zero is an error). Exits 2 if any file cannot be read.

use strict;
use warnings;

# Attribute grammar: a name (no whitespace, '=', '>', or '/'), optionally
# followed by = and a double-quoted, single-quoted, or bare value. Because
# quoted values are matched with "[^"]*" / '[^']*', a '>' or whitespace
# inside a quoted value does not end the attribute or the tag.
my $ATTR = qr/\s+[^\s=>\/]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?/;
my $TAG_RE = qr/<script\b((?:$ATTR)*)\s*\/?>/is;
my $ATTR_RE = qr/([^\s=>\/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/s;

my $had_error = 0;

for my $file (@ARGV) {
    my $content;
    my $ok = open(my $fh, '<:raw', $file);
    if ($ok) {
        local $/;
        $content = <$fh>;
        close $fh;
    }
    if (!$ok || !defined $content) {
        print STDERR "script-tags.pl: cannot read '$file': $!\n";
        exit 2;
    }

    # Comment spans computed on the ORIGINAL content, used only to filter
    # out tags that live inside a comment. Byte offsets printed below stay
    # relative to the original file.
    my @comment_spans;
    while ($content =~ /<!--.*?-->/gs) {
        push @comment_spans, [$-[0], $+[0]];
    }
    my $in_comment = sub {
        my ($pos) = @_;
        for my $span (@comment_spans) {
            return 1 if $pos >= $span->[0] && $pos < $span->[1];
        }
        return 0;
    };

    while ($content =~ /$TAG_RE/g) {
        my $offset = $-[0];
        next if $in_comment->($offset);

        my $raw = $&;
        my $attrs_str = defined $1 ? $1 : '';

        my %attrs;
        while ($attrs_str =~ /$ATTR_RE/g) {
            my $name = lc($1);
            my $value;
            if (defined $2) {
                $value = $2;
            } elsif (defined $3) {
                $value = $3;
            } elsif (defined $4) {
                $value = $4;
            } else {
                $value = '';
            }
            # Browsers are first-wins for duplicate attributes: the first
            # occurrence of a given attribute name in a tag is the one that
            # takes effect, later ones are ignored. Only set it once.
            $attrs{$name} = $value unless exists $attrs{$name};
        }

        my $src = exists $attrs{src} ? $attrs{src} : '';
        $src =~ s/^[ \t\n\r\f]+//;
        $src =~ s/[ \t\n\r\f]+$//;

        my $integrity = exists $attrs{integrity} ? $attrs{integrity} : '';

        (my $raw_line = $raw) =~ s/\n/ /g;

        print join("\t", $file, $src, $integrity, $offset, $raw_line), "\n";
    }
}

exit 0;
