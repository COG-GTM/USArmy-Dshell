import dshell.core
from dshell.util import printable_text
from dshell.output.alertout import AlertOutput
from dshell.security.validation import (
    safe_compile_regex,
    regex_search_with_timeout,
    RegexValidationError,
    RegexTimeoutError,
    DEFAULT_REGEX_TIMEOUT,
)

import re
import sys

class DshellPlugin(dshell.core.ConnectionPlugin):

    def __init__(self):
        super().__init__(
            name="search",
            author="dev195",
            bpf="tcp or udp",
            description="Search for patterns in connections",
            longdescription="""
Reconstructs streams and searches the content for a user-provided regular
expression. Requires definition of the --search_expression argument. Additional
options can be provided to alter behavior.

Security: This plugin includes ReDoS (Regular Expression Denial of Service)
protection with configurable timeout and pattern validation.
            """,
            output=AlertOutput(label=__name__),
            optiondict={
                "expression": {
                    "help": "Search expression",
                    "type": str,
                    "metavar": "REGEX"},
                "ignorecase": {
                    "help": "Ignore case when searching",
                    "action": "store_true"},
                "invert": {
                    "help": "Return connections that DO NOT match expression",
                    "action": "store_true"},
                "quiet": {
                    "help": "Do not display matches from this plugin. Useful when chaining plugins.",
                    "action": "store_true"},
                "regex_timeout": {
                    "help": "Timeout in seconds for regex operations (default: 5.0)",
                    "type": float,
                    "default": DEFAULT_REGEX_TIMEOUT,
                    "metavar": "SECONDS"},
                "skip_validation": {
                    "help": "Skip regex pattern validation (not recommended)",
                    "action": "store_true"}
            })



    def premodule(self):
        # make sure the user actually provided an expression to search for
        if not self.expression:
            self.error("Must define an expression to search for using --search_expression")
            sys.exit(1)

        # define the regex flags, based on arguments
        re_flags = 0
        if self.ignorecase:
            re_flags = re_flags | re.IGNORECASE

        # Store timeout for use in connection_handler
        self._regex_timeout = getattr(self, 'regex_timeout', DEFAULT_REGEX_TIMEOUT)
        self._skip_validation = getattr(self, 'skip_validation', False)

        # Create the regular expression with security validation
        try:
            # convert expression to bytes so it can accurately compare to
            # the connection data (which is also of type bytes)
            byte_expression = bytes(self.expression, 'utf-8')

            # Use safe_compile_regex for ReDoS protection
            self.regex = safe_compile_regex(
                byte_expression,
                flags=re_flags,
                timeout=self._regex_timeout,
                validate=not self._skip_validation
            )
        except RegexValidationError as e:
            self.error("Regex validation failed: {0}".format(e))
            self.error("Use --search_skip_validation to bypass (not recommended)")
            sys.exit(1)
        except RegexTimeoutError:
            self.error("Regex compilation timed out after {0} seconds".format(self._regex_timeout))
            self.error("Pattern may be too complex. Try simplifying or increase --search_regex_timeout")
            sys.exit(1)
        except Exception as e:
            self.error("Could not compile regex ({0})".format(e))
            sys.exit(1)



    def connection_handler(self, conn):
        """
        Go through the data of each connection.
        If anything is a hit, return the entire connection.

        Security: Uses timeout-protected regex search to prevent ReDoS attacks.
        """

        match_found = False
        for blob in conn.blobs:
            for line in blob.data.splitlines():
                try:
                    # Use timeout-protected regex search
                    match = regex_search_with_timeout(
                        self.regex, line, timeout=self._regex_timeout
                    )
                except RegexTimeoutError:
                    self.warn("Regex search timed out for connection {0}".format(conn.addr))
                    continue

                if match and self.invert:
                    return None
                elif match and not self.invert:
                    match_found = True
                    if not self.quiet:
                        if blob.sip == conn.sip:
                            self.write(printable_text(line, False), **conn.info(), dir_arrow="->")
                        else:
                            self.write(printable_text(line, False), **conn.info(), dir_arrow="<-")
                elif self.invert and not match:
                    if not self.quiet:
                        self.write(**conn.info())
                    return conn
        if match_found:
            return conn



if __name__ == "__main__":
    print(DshellPlugin())
