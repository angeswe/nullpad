#!/bin/bash
# Update SRI (Subresource Integrity) hashes in all HTML files.
# Run after modifying any JS file in static/js/.

set -euo pipefail
cd "$(dirname "$0")/.."

STATIC_DIR="${STATIC_DIR:-static}"
HTML_FILES=$(find "$STATIC_DIR" -name "*.html" -maxdepth 1)
# Also include protected HTML files (served via auth-gated route handlers)
if [ -d "protected" ]; then
  HTML_FILES="$HTML_FILES $(find "protected" -name "*.html" -maxdepth 1)"
fi

SCRIPT_TAGS_PL="tools/lib/script-tags.pl"

# Generate SRI hash for a file
sri_hash() {
  echo "sha384-$(openssl dgst -sha384 -binary "$1" | openssl base64 -A)"
}

# For each JS file referenced in HTML, update its integrity attribute.
#
# script-tags.pl finds every <script ...> tag with a grammar-correct
# parser (a '>' inside a quoted attribute value does not end the tag, and
# a commented-out tag is never seen), and reports each tag's exact raw
# text plus its byte offset in the file. That offset is used to splice the
# rewritten tag back into the file at the exact same bytes, so this is a
# targeted replacement of the original bytes rather than a fresh regex
# match against the file — no risk of matching a different occurrence of
# the same tag text, and no risk of touching anything inside a comment.
# Every other attribute (defer, async, ...) and its original quoting is
# left exactly where it was; only integrity/crossorigin are stripped and
# re-appended with fresh values.
for html in $HTML_FILES; do
  if ! tag_output=$(perl "$SCRIPT_TAGS_PL" "$html"); then
    echo "ERROR: script-tags.pl failed to parse $html" >&2
    exit 1
  fi

  STATIC_DIR="$STATIC_DIR" HTML_PATH="$html" perl -e '
    my $static_dir = $ENV{STATIC_DIR};
    my $html_path = $ENV{HTML_PATH};

    open(my $fh, "<:raw", $html_path) or die "cannot read $html_path: $!\n";
    my $content = do { local $/; <$fh> };
    close $fh;

    my @tags;
    while (my $line = <STDIN>) {
      chomp $line;
      next if $line eq "";
      my ($file, $src, $integrity, $offset, $raw) = split /\t/, $line, 5;
      next unless defined $src && $src ne "";
      # Only rewrite site-relative srcs (a single leading "/"; not
      # "//host" and not "http(s)://..."). Those used to be filtered down
      # to a literal "^/js/" prefix, which silently left a tag like
      # "/jsx/../js/x.js" (resolves in the browser to /js/x.js) or any
      # site-relative tag outside /js/ untouched. Inline tags (no src) and
      # non-site-relative tags (protocol or protocol-relative) are left
      # alone here too -- verify-vendor.sh is the enforcer for those, not
      # this rewriter.
      next if $src =~ m{^//};
      next if $src =~ m{^[a-zA-Z][a-zA-Z0-9+.\-]*:};
      next unless $src =~ m{^/};
      push @tags, { offset => $offset, raw => $raw, src => $src };
    }

    # Rewrite from the end of the file backwards so earlier splices do not
    # shift the byte offsets of tags still to be rewritten.
    @tags = sort { $b->{offset} <=> $a->{offset} } @tags;

    use Cwd qw(getcwd);
    use Cwd ();
    use File::Spec;

    # Lexical equivalent of `realpath -m`: normalizes "." and ".."
    # components and returns an absolute path, without requiring any
    # component to actually exist. Cwd::realpath cannot be used here
    # because a src like "/jsx/../js/x.js" has a nonexistent "jsx"
    # component that only ever appears as part of a ".." traversal --
    # Cwd::realpath refuses to resolve through it even though the final
    # target exists.
    sub realpath_m {
      my ($path) = @_;
      $path = File::Spec->rel2abs($path, getcwd());
      my @out;
      for my $part (File::Spec->splitdir($path)) {
        next if $part eq "" || $part eq ".";
        if ($part eq "..") {
          pop @out if @out;
        } else {
          push @out, $part;
        }
      }
      return "/" . join("/", @out);
    }

    my $static_root_real = realpath_m($static_dir);

    for my $t (@tags) {
      my $offset = $t->{offset};
      my $raw = $t->{raw};
      my $len = length($raw);
      my $original = substr($content, $offset, $len);

      # The src to hash comes from the grammar-correct parse done by
      # script-tags.pl (already trimmed and first-wins for duplicate attributes),
      # never re-derived from the raw tag text. A regex re-extraction
      # here (e.g. /\bsrc=.../) is unsafe: \b matches right after the
      # hyphen in "data-src=", so a tag like
      # <script data-src="/js/evil.js" src="/js/legit.js"> would have
      # the evil.js hash written instead of the legit.js one.
      my $file_path = "$static_dir$t->{src}";

      # Canonicalize and confine: a site-relative src must resolve to a
      # real file inside static_dir/. Without this, a src like
      # "/jsx/../js/x.js" or "/../secret.js" could be rewritten with a
      # hash of a file outside the static tree (or in a different
      # subdirectory) while looking harmless in the HTML.
      my $file_path_real = realpath_m($file_path);

      unless (defined $file_path_real && -f $file_path_real) {
        die "$file_path not found (referenced in $html_path)\n";
      }
      unless (defined $static_root_real && index($file_path_real, "$static_root_real/") == 0) {
        die "$file_path escapes $static_dir (resolves to " . ($file_path_real // "undef") . ") referenced in $html_path\n";
      }

      # The lexical check above only normalizes "." and ".." components; it
      # does not follow symlinks, so a symlink under static/ pointing
      # outside it (e.g. static/js/linked -> /somewhere/else) would pass
      # the check above while resolving to a file outside the static tree.
      # The file is known to exist at this point, so resolve it for real
      # with Cwd::realpath (which does follow symlinks) and re-check
      # confinement against the similarly-resolved static root.
      my $file_path_resolved = Cwd::realpath($file_path_real);
      my $static_root_resolved = Cwd::realpath($static_dir);
      unless (defined $file_path_resolved
        && defined $static_root_resolved
        && index($file_path_resolved, "$static_root_resolved/") == 0) {
        die "$file_path escapes $static_dir via a symlink (resolves to "
          . ($file_path_resolved // "undef") . ") referenced in $html_path\n";
      }
      $file_path = $file_path_real;

      my $b64 = `openssl dgst -sha384 -binary "$file_path" | openssl base64 -A`;
      chomp $b64;
      my $hash = "sha384-$b64";

      (my $new = $original) =~ s/\s+integrity\s*=\s*(["\x27])[^"\x27]*\1//g;
      $new =~ s/\s+crossorigin\s*=\s*(["\x27])[^"\x27]*\1//g;
      unless ($new =~ s/\s*\/?>\s*$/ integrity="$hash" crossorigin="anonymous">/) {
        die "could not rewrite tag ending while updating $html_path at offset $offset: $new\n";
      }

      substr($content, $offset, $len) = $new;
    }

    open(my $out, ">:raw", $html_path) or die "cannot write $html_path: $!\n";
    print $out $content;
    close $out;
  ' <<< "$tag_output"
  echo "Updated: $html"
done

# For each CSS file referenced in HTML, update its integrity attribute
for html in $HTML_FILES; do
  grep -oP 'href="/css/[^"]+' "$html" | sed 's/^href="//' | while read -r href_path; do
    file_path="${STATIC_DIR}${href_path}"
    if [ ! -f "$file_path" ]; then
      echo "WARNING: $file_path not found (referenced in $html)"
      continue
    fi

    hash=$(sri_hash "$file_path")

    # Replace: href="/css/..." with or without existing integrity
    sed -i "s|href=\"${href_path}\"[^>]*>|href=\"${href_path}\" integrity=\"${hash}\" crossorigin=\"anonymous\">|g" "$html"
  done || true
done

echo "SRI hashes updated."
