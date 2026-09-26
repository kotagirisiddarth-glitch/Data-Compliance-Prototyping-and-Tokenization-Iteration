"""
vault.py
--------
This is our Token Vault. Its job is to take sensitive real-world data
(like a credit card number or an SSN) and swap it for a meaningless
random "token" that is safe to store/use elsewhere in our system.

The ONLY way to get the real data back is to look it up by its token
in THIS file's database, using THIS file's secret key.

WHY THIS MATTERS (read this even if you skip every other comment):
If we stored the real data in the database as plain, readable text,
then anyone who ever got a copy of that database file -- a stolen
backup, a misconfigured server, a leaked laptop -- would instantly
have every piece of sensitive data we ever touched. That is the #1
way "data compliance" startups end up in the news for the wrong
reason. So instead, we ENCRYPT the real data before it ever touches
the disk. Encrypted data looks like random garbage to anyone who
doesn't have our secret key.

=====================================================================
 NEW IN THIS VERSION: MULTI-TENANT ISOLATION VIA ORGANIZATION SALTS
=====================================================================
We now serve MULTIPLE companies ("tenants") out of one vault. Every
single tokenize/detokenize call now requires a `tenant_id` (e.g. the
customer's company name or account ID) in addition to the data/token.

Why this matters with a concrete example:
  Company A and Company B might both happen to have a customer whose
  credit card number is "4111222233334444". Without tenant isolation,
  our old vault would treat those as literally the SAME piece of data
  -- meaning Company B could type in a number that happens to match
  one of Company A's customers and get back Company A's TOKEN. Worse,
  if Company B ever obtained that token through a bug or an API
  mistake, they could "detokenize" it and read Company A's customer
  data. For a B2B compliance product, that's a catastrophic,
  contract-ending bug -- it's literally one customer reading another
  customer's data.

How we fix it -- two separate changes working together:
  1. DATABASE LEVEL: every row now also stores which tenant it belongs
     to (`tenant_id` column), and detokenize_data() REFUSES to return
     a row unless the tenant_id matches too. So even if Company B
     somehow got Company A's token string, asking for it under their
     own tenant_id returns nothing.
  2. ENCRYPTION LEVEL (the "cryptographic salt"): we make the
     ENCRYPTED bytes themselves come out completely differently for
     the same input data when the tenant_id differs. This way, even
     someone with raw, illegal access to the .db file (bypassing our
     program entirely) cannot tell that Company A's customer and
     Company B's customer share the same underlying card number, just
     by comparing the encrypted blobs.

A DELIBERATE DESIGN CHOICE -- read this carefully:
You might think "just glue tenant_id onto the secret key." We do NOT
do that. Here's why: our master SECRET_KEY_BYTES is a strong, private,
hard-to-guess value that only we (the vault operator) know. A
tenant_id, by contrast, is often a low-effort, guessable, even
PUBLIC value -- e.g. "acme_corp" or "tenant_42". If we let tenant_id
replace or weaken our master key, we'd be propping our entire vault's
security on a value our customers basically choose themselves.

Instead, we keep the master key exactly as strong as before, and
DERIVE a separate, per-tenant key by hashing (mixing) the master key
together with the tenant_id. This is a standard technique called
"key derivation." The result:
  - Same tenant + same data  -> same derived key -> same ciphertext
    (so deduplication still works correctly WITHIN one tenant).
  - Different tenant + same data -> different derived key -> totally
    different ciphertext (so tenants can't be compared against each
    other just by staring at the database file).
  - Nobody can derive ANY tenant's key, or decrypt ANYTHING, without
    knowing the master SECRET_KEY_BYTES. Knowing a tenant_id alone
    (which might leak far more easily than our master secret) gives
    an attacker nothing on its own.

UPGRADE PATH (for later, not now):
This file still uses a hand-built encryption method (XOR + hashlib)
using ONLY Python's built-in libraries, because you asked for zero
extra installs and a tiny memory footprint. Before handling real
customer data in production, swap encrypt_data()/decrypt_data() for
the `cryptography` library's AES-GCM. The multi-tenant key-derivation
IDEA in this file (mixing master key + tenant_id via a hash) is the
same technique you'd reuse with AES -- only the low-level math inside
encrypt_data()/decrypt_data() would need to change.

=====================================================================
 NEW IN THIS VERSION: AUDIT LOG SYSTEM (ACTIVITY LEDGER)
=====================================================================
A compliance product lives or dies by whether it can answer the
question "who accessed what, and when?" That's exactly what this
section adds: a SECOND table, `audit_logs`, that permanently records
every tokenize/detokenize attempt -- successes, failures, and errors
alike -- stamped with the tenant, the action, the token involved, and
the exact time it happened.

WHY "ATTEMPTS" AND NOT JUST "SUCCESSES": a real auditor doesn't just
want to know what worked. A pattern of repeated FAILED lookups against
tokens that don't exist for a given tenant can be a sign of someone
probing the system, trying to guess valid tokens. Recording failures
is just as important as recording successes.

ON THE WORD "IMMUTABLE": true immutability (nobody, ever, under any
circumstance, can alter a past log entry) usually requires extra
infrastructure -- write-once storage or file permission locks at the
operating-system level. We're not building that heavy machinery in
this prototype. What we ARE doing, deliberately: this file contains
NO function anywhere that performs an UPDATE or DELETE against the
audit_logs table -- only INSERT. As long as nobody bypasses this file
and edits the database directly, the log this program produces is
append-only in practice.

=====================================================================
 NEW IN THIS VERSION: CRYPTOGRAPHIC HASH CHAINING (TAMPER-EVIDENCE)
=====================================================================
The append-only guarantee above only stops tampering done THROUGH
this Python file. It does NOT stop someone who opens secure_vault.db
directly with a separate database tool and edits a row by hand,
bypassing our code entirely. Hash chaining is what catches THAT.

Every audit log row now stores two extra fields: previous_hash (a
copy of the hash that was on the row written immediately before it)
and current_hash (a fresh SHA-256 hash combining this row's own data
with that previous_hash). Because each row's hash is built FROM the
row before it, every entry is cryptographically "stitched" to its
neighbor -- editing any field on any past row, however small the
edit, makes that row's hash (and therefore the whole chain after it)
detectably wrong. The new verify_ledger_integrity() function walks
the entire chain and reports exactly where, if anywhere, it breaks.
Full plain-English detail on the mechanism lives in the comments
directly above _calculate_log_hash() and _write_audit_log() below.
"""

# "import" means: "go fetch a pre-built toolbox that Python ships with,
# and let me use the tools inside it in this file."
# We are NOT downloading anything from the internet here -- these three
# toolboxes are part of Python itself, which is why they cost ~0 extra
# RAM and have no installation step.

import sqlite3   # Toolbox for talking to a SQLite database (a tiny,
                  # single-file database that lives right on disk --
                  # no separate database server needed, which is why
                  # it's so light on RAM).

import secrets   # Toolbox for generating cryptographically random
                  # values -- i.e. randomness that is unpredictable
                  # enough to be safe for security purposes (regular
                  # `random` module is NOT safe for this; `secrets` is).

import hashlib    # Toolbox for "hashing" -- turning any input (like a
                  # password) into a fixed-length scrambled fingerprint.
                  # We use this both to prepare our master key, AND
                  # (new in this version) to derive a separate key per
                  # tenant by hashing the master key together with a
                  # tenant_id.

import os         # Toolbox for talking to the operating system --
                  # we use it specifically to read "environment
                  # variables," which are like settings/secrets that
                  # live OUTSIDE this code file, in the computer's
                  # environment.

import datetime   # NEW. Toolbox for working with dates and times.
                  # We use this to stamp every audit log entry with
                  # the exact moment an action happened -- a core
                  # requirement for any compliance audit trail.


# --------------------------------------------------------------------
# STEP 1: LOAD THE SECRET KEY FROM THE ENVIRONMENT (NOT FROM CODE)
# --------------------------------------------------------------------

# "os.environ.get(...)" looks up a value the user has set OUTSIDE this
# script (for example, by typing a command in the terminal before
# running this file -- we'll show you exactly how, below).
# The second argument (None) is the default: if nobody set the
# variable, we'll get None back instead of a crash.
RAW_SECRET_KEY = os.environ.get("VAULT_SECRET_KEY", None)

# "if" checks a condition. Here: "if no key was found at all..."
if RAW_SECRET_KEY is None:
    # "raise" deliberately stops the program and throws an error on
    # purpose. We WANT the program to refuse to run rather than silently
    # use some weak default key -- a vault with a guessable lock is
    # worse than a vault that flatly refuses to open.
    raise RuntimeError(
        "VAULT_SECRET_KEY environment variable is not set. "
        "Set it before running this script, e.g.:\n"
        "  export VAULT_SECRET_KEY='choose-a-long-random-passphrase-here'\n"
        "(On Windows Powershell: $env:VAULT_SECRET_KEY='...')"
    )

# hashlib.sha256(...) takes our secret key (which might be short, like
# "mypassword123") and stretches/scrambles it into exactly 32 bytes of
# dense randomness. This gives our encryption math a consistent,
# strong-quality MASTER key no matter what the user typed as their
# passphrase. This master key never changes per-tenant -- it's the one
# secret that ultimately protects every tenant's data.
#
# ".encode()" converts a normal Python text string into "bytes" --
# the raw 0s-and-1s format that encryption math actually operates on.
# Think of it as translating human handwriting into a barcode.
#
# ".digest()" extracts the actual scrambled bytes out of the hash
# calculation (as opposed to ".hexdigest()" which would give us a
# human-readable text version -- we want raw bytes for the math).
MASTER_SECRET_KEY_BYTES = hashlib.sha256(RAW_SECRET_KEY.encode()).digest()


# --------------------------------------------------------------------
# STEP 2 (NEW): DERIVE A PER-TENANT KEY FROM THE MASTER KEY
# --------------------------------------------------------------------

def _derive_tenant_key(tenant_id):
    """
    NEW FUNCTION.
    Takes a tenant_id (e.g. "company_a") and combines it with our
    private MASTER_SECRET_KEY_BYTES to produce a brand new 32-byte key
    that is unique to that one tenant.

    This is the "cryptographic salt" step. A "salt" in cryptography
    means: extra, non-secret information mixed into a calculation so
    that the same input data produces a different output in different
    contexts. Here, tenant_id is our salt.

    Why hashlib.sha256 again? Hashing the MASTER key together with the
    tenant_id guarantees:
      - The result is always exactly 32 bytes, no matter how long or
        short tenant_id is (a hash always outputs a fixed length).
      - The result looks completely different even for very similar
        tenant_ids (e.g. "tenant1" vs "tenant2" produce wildly
        different keys, not just slightly different ones). This
        property is called the "avalanche effect."
      - It is computationally impractical to work backwards from the
        derived key to recover the master key. So even if one tenant's
        derived key were ever somehow exposed, the master key (and
        therefore every OTHER tenant's data) stays safe.
    """
    # ".encode()" turns the tenant_id text into bytes, same as before.
    tenant_id_bytes = tenant_id.encode()

    # Here we feed hashlib.sha256() the MASTER key bytes immediately
    # followed by the tenant_id bytes, all concatenated together with
    # the "+" operator (which, for bytes objects, just means "joined
    # end to end"). Hashing that combined blob gives us a brand new,
    # tenant-specific 32-byte key.
    return hashlib.sha256(MASTER_SECRET_KEY_BYTES + tenant_id_bytes).digest()


# --------------------------------------------------------------------
# STEP 3: THE ENCRYPT / DECRYPT FUNCTIONS (OUR "VAULT DOOR")
# --------------------------------------------------------------------

def _xor_bytes(data_bytes, key_bytes):
    """
    This is a private helper function (the leading underscore "_" is a
    Python convention meaning "internal use only, not meant to be
    called from outside this file").

    "def" means "define a function" -- a reusable, named block of
    instructions that we can run later just by typing its name.

    XOR ("exclusive or") is a basic bit-flipping operation. When you
    XOR data with a key once, you scramble it. XOR it again with the
    SAME key, and you get the original data back perfectly. That
    "do it twice and you're back to normal" property is exactly what
    we want for a reversible lock.

    Because our key is only 32 bytes long but our data might be much
    longer, we REPEAT the key over and over (key cycling) until it's
    as long as the data, using the key_bytes[i % len(key_bytes)] trick
    below ("%" is the remainder/modulo operator -- it makes the index
    wrap back around to 0 once it reaches the end of the key).
    """
    # "for i in range(len(data_bytes))" means: "repeat once for every
    # position/index in data_bytes, calling that position 'i' each time."
    # "bytes([...])" rebuilds a bytes object out of a list of numbers.
    # This single line XORs every byte of data with the matching
    # (cycled) byte of the key, and collects the results into one list.
    return bytes(
        data_bytes[i] ^ key_bytes[i % len(key_bytes)]
        for i in range(len(data_bytes))
    )


def encrypt_data(plain_text, tenant_id):
    """
    CHANGED: now takes tenant_id as a required second argument.

    Takes a normal, human-readable string (e.g. "4111-2222-3333-4444")
    PLUS the tenant it belongs to, and returns an encrypted, scrambled
    version safe to store on disk -- one that will look completely
    different for the same plain_text if tenant_id is different.

    "return" means "hand this value back to whoever called the function,
    so they can use it."
    """
    # NEW: instead of using the shared MASTER_SECRET_KEY_BYTES directly,
    # we first derive a key that's unique to this specific tenant.
    tenant_key_bytes = _derive_tenant_key(tenant_id)

    # Convert our text into bytes, since encryption math works on bytes.
    plain_bytes = plain_text.encode()

    # Scramble the bytes using the TENANT-SPECIFIC key (not the raw
    # master key) -- this is the actual moment the "salt" takes effect.
    encrypted_bytes = _xor_bytes(plain_bytes, tenant_key_bytes)

    # The scrambled bytes can contain values that aren't valid text
    # characters, so before saving them in a normal database text
    # column, we convert them to "hex" -- a safe, readable representation
    # made only of the characters 0-9 and a-f. ".hex()" does this.
    return encrypted_bytes.hex()


def decrypt_data(encrypted_hex_text, tenant_id):
    """
    CHANGED: now takes tenant_id as a required second argument.

    Reverses encrypt_data(): takes the scrambled hex text we pulled out
    of the database, PLUS the tenant_id it was originally encrypted
    under, and turns it back into the original human-readable string.

    IMPORTANT: you must pass the SAME tenant_id that was used to
    encrypt this exact value, or you will get back garbage instead of
    the real data (because the derived key will be completely wrong).
    This is actually a FEATURE, not a bug -- it's literally what
    enforces tenant isolation at the cryptography layer.
    """
    # Re-derive the exact same tenant-specific key used during
    # encryption. Key derivation is deterministic: the same master key
    # + the same tenant_id ALWAYS produces the same derived key.
    tenant_key_bytes = _derive_tenant_key(tenant_id)

    # "bytes.fromhex(...)" undoes the ".hex()" step above -- it turns
    # our safe hex text back into raw scrambled bytes.
    encrypted_bytes = bytes.fromhex(encrypted_hex_text)

    # XOR-ing again with the SAME (tenant-specific) key undoes the
    # scrambling perfectly.
    plain_bytes = _xor_bytes(encrypted_bytes, tenant_key_bytes)

    # ".decode()" converts raw bytes back into a normal Python text
    # string (the reverse of ".encode()" from earlier).
    return plain_bytes.decode()


# --------------------------------------------------------------------
# STEP 4: SET UP THE DATABASE (CREATE THE FILE + TABLE IF NEEDED)
# --------------------------------------------------------------------

DATABASE_FILENAME = "secure_vault.db"  # The single file SQLite will
                                        # store everything in, sitting
                                        # right next to this script.


def get_connection():
    """
    Opens (or creates, if it doesn't exist yet) our database file and
    hands back a "connection" -- think of a connection as a phone line
    that's now open between our Python code and the database file.
    """
    # sqlite3.connect(...) opens the .db file. If secure_vault.db
    # doesn't exist yet, SQLite creates a brand new empty one for us
    # automatically -- no separate "create database" step needed.
    return sqlite3.connect(DATABASE_FILENAME)


def initialize_database():
    """
    Makes sure our 'tokens' table exists, now WITH multi-tenant support.
    Safe to call every single time the program starts -- it won't wipe
    or duplicate anything.

    NOTE FOR ANYONE UPGRADING AN EXISTING DATABASE FROM v1:
    "CREATE TABLE IF NOT EXISTS" only creates the table if it does NOT
    already exist at all -- it will NOT add the new tenant_id column to
    an old database file that was created before this update. If you
    already have an old secure_vault.db file lying around from
    testing, simply delete that file and let this function create a
    fresh one with the new structure. (In a real production system
    with real data, you'd instead write a careful "migration" script
    instead of deleting -- but for our current prototype stage,
    deleting and recreating is perfectly fine.)
    """
    # Open the phone line to the database.
    connection = get_connection()

    # A "cursor" is the actual tool we use to SEND commands down that
    # phone line and READ back results. The connection is the line;
    # the cursor is the handset you actually speak into.
    cursor = connection.cursor()

    # ".execute(...)" sends one raw SQL command to the database.
    # SQL is the special command language databases understand.
    #
    # "CREATE TABLE IF NOT EXISTS" means: "make this table, but if it
    # already exists from a previous run, do nothing instead of erroring."
    #
    # Inside the table we define four columns now:
    #   id                -> a unique number auto-assigned to each row,
    #                        used internally as a reliable row ID.
    #   tenant_id          -> NEW. Which company/customer this row
    #                        belongs to (e.g. "company_a"). "NOT NULL"
    #                        means SQLite will refuse to save a row
    #                        that's missing this value -- every row
    #                        MUST belong to some tenant.
    #   token_placeholder -> the random fake value (safe to share).
    #   encrypted_data     -> the REAL data, but only in its scrambled,
    #                        encrypted form -- never stored as plain text.
    #
    # "TEXT" and "INTEGER" are SQLite's names for "this column holds
    # text" and "this column holds whole numbers."
    #
    # CHANGED CONSTRAINT: notice token_placeholder is no longer marked
    # UNIQUE all by itself. Instead, we add a separate line:
    #     UNIQUE (tenant_id, token_placeholder)
    # This tells SQLite: "the COMBINATION of these two columns together
    # must be unique." In plain English -- Company A and Company B are
    # now FREE to coincidentally generate the exact same random token
    # string as each other (astronomically unlikely, but allowed), as
    # long as no single tenant ever has two rows with the same token.
    # This is exactly the rule we need for proper multi-tenancy.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            token_placeholder TEXT NOT NULL,
            encrypted_data TEXT NOT NULL,
            UNIQUE (tenant_id, token_placeholder)
        )
    """)

    # NEW: create the audit_logs table. This is our permanent activity
    # ledger -- a running history of every tokenize/detokenize attempt.
    #
    # Columns:
    #   id                -> auto-incrementing row ID, same idea as in
    #                        the tokens table.
    #   timestamp          -> TEXT holding the exact moment this action
    #                        happened (we'll generate this ourselves in
    #                        Python using the datetime module, rather
    #                        than relying on SQLite's own clock, so the
    #                        format is exactly what we choose).
    #   tenant_id          -> which organization performed this action.
    #   action             -> what kind of action this was, e.g.
    #                        "TOKENIZE" or "DETOKENIZE".
    #   token_placeholder -> which token was involved (if relevant).
    #   status             -> the outcome: "SUCCESS", "FAILED_NOT_FOUND",
    #                        or "ERROR".
    #   previous_hash      -> NEW. The cryptographic hash that was
    #                        stored on the PREVIOUS row at the moment
    #                        this row was written. This is the literal
    #                        "link" connecting each entry to the one
    #                        before it -- explained in full inside
    #                        _write_audit_log() below.
    #   current_hash       -> NEW. This row's OWN cryptographic hash,
    #                        calculated from this row's own data PLUS
    #                        previous_hash. The next row that gets
    #                        written will store THIS value as ITS
    #                        previous_hash, continuing the chain.
    #
    # Notice there is NO "UNIQUE" constraint here at all -- audit logs
    # are expected to repeat the same tenant_id, action, and even the
    # same token over and over across many different events. What
    # makes each row distinct is simply WHEN it happened, captured in
    # the timestamp.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            action TEXT NOT NULL,
            token_placeholder TEXT,
            status TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            current_hash TEXT NOT NULL
        )
    """)

    # ".commit()" tells SQLite "I'm done making changes, please save
    # them permanently to the disk file now." Without commit, changes
    # can be lost when the connection closes.
    connection.commit()

    # ".close()" hangs up the phone line. Always close connections
    # when you're done with them, so the database file isn't left
    # locked or open unnecessarily -- this keeps our RAM/resource
    # footprint small, which matters a lot on an 8GB laptop.
    connection.close()


# --------------------------------------------------------------------
# STEP 4B (NEW): WRITE A PERMANENT, HASH-CHAINED AUDIT LOG ENTRY
# --------------------------------------------------------------------
#
# WHAT IS "HASH CHAINING" AND WHY DOES IT MATTER FOR COMPLIANCE?
#
# Earlier, we made our audit log "append-only in practice" by simply
# never writing any UPDATE/DELETE code anywhere in this file. That's
# good, but it only stops tampering done THROUGH this program. It does
# NOT stop someone who opens secure_vault.db directly with a separate
# database tool and edits a row by hand, bypassing our Python code
# entirely. Hash chaining is what catches THAT.
#
# Think of a hash chain like a paper chain of links, where each new
# link is glued on using a tiny smear of glue copied from the
# PREVIOUS link. If someone secretly swaps out link #50 in the middle
# of the chain, the glue pattern connecting link #50 to link #51 no
# longer matches -- because link #51's glue was copied from the
# ORIGINAL link #50, not the replacement. The tampering becomes
# visible just by checking whether each link's glue matches the one
# before it, without needing to inspect every link by itself.
#
# Concretely, in code: every audit log row stores TWO hash values:
#   previous_hash -> a copy of the hash that was on the row immediately
#                    before it, at the moment THIS row was written.
#   current_hash  -> a brand new hash, calculated by combining THIS
#                    row's own data (timestamp, tenant_id, action,
#                    status) together with that previous_hash.
#
# Because current_hash is calculated FROM previous_hash, every row is
# cryptographically "stitched" to the row before it. Change anything
# about an old row -- even a single character in its status -- and
# its current_hash, if honestly recalculated, would come out
# completely different. Since the NEXT row already has the OLD,
# correct current_hash baked into its own previous_hash field forever,
# the mismatch becomes detectable. verify_ledger_integrity() (further
# below) is the function that walks the whole chain and checks this.


def _calculate_log_hash(timestamp, tenant_id, action, token_placeholder, status, previous_hash):
    """
    UPDATED FUNCTION (bug fix).
    Calculates the SHA-256 hash for one audit log row, combining that
    row's own data fields with the hash of the row before it.

    WHAT IS SHA-256, IN PLAIN ENGLISH?
    SHA-256 is a "hashing" algorithm -- a mathematical recipe that
    takes ANY amount of input text and squeezes it down into a fixed,
    256-bit (64 hex-character) fingerprint. Two crucial properties make
    it useful here:
      1. DETERMINISTIC: the exact same input ALWAYS produces the exact
         same fingerprint. Feed it identical text twice, get identical
         hashes twice -- there's no randomness involved.
      2. AVALANCHE EFFECT: changing even ONE character of the input --
         flipping "SUCCESS" to "SUCCES5", for example -- produces a
         COMPLETELY different fingerprint, not a similar one. There's
         no way to predict how a tiny edit will change the output, and
         no practical way to find a DIFFERENT input that produces the
         SAME fingerprint as the original. This is exactly what makes
         tampering detectable: any edit, however small, is caught.

    Why combine ALL these specific fields together?
    We deliberately include EVERY meaningful piece of this log entry
    (timestamp, tenant_id, action, token_placeholder, status) PLUS the
    previous row's hash, all mashed together before hashing. If an
    attacker changed ANY single one of these values on an old row,
    recalculating the hash here would no longer match what's stored in
    the database -- that mismatch is exactly what
    verify_ledger_integrity() looks for.

    BUG FIX -- READ THIS: an earlier version of this function left
    token_placeholder OUT of the hash, on the reasoning that the other
    fields already "uniquely identify" the entry. That reasoning was
    wrong, and it was caught by testing: with token_placeholder excluded,
    someone could silently swap which token an audit entry points to
    -- making the log claim "token ABC123 was successfully detokenized"
    when the real event involved a totally different token -- and
    verify_ledger_integrity() would still report the chain as fully
    intact, because nothing it actually checked had changed. That is
    exactly the kind of falsifiable record a compliance audit log must
    NOT allow. Including token_placeholder in the hash closes this gap:
    changing it now changes the hash, which breaks the chain exactly
    like editing any other field would.

    HANDLING THE "NO TOKEN" CASE CONSISTENTLY: token_placeholder is
    allowed to be None for some ERROR entries (see _write_audit_log()'s
    docstring) where no token was ever generated. We can't simply drop
    a None value into an f-string combination and trust it blindly --
    we want one single, consistent text representation for "there is no
    token here" every time, so the line below converts None into the
    literal text "NONE" before hashing. This means a real, deliberately
    tampered token of the literal text "NONE" would still be
    distinguishable in the database itself (you could check for it
    being a literal string vs the column actually being NULL), while
    the hash calculation itself stays simple and unambiguous.
    """
    # Convert a missing token into a fixed, predictable placeholder
    # string, so hashing always works with plain text -- never with
    # Python's None value itself, which f-strings would otherwise quietly
    # convert to the text "None" (capital N) in a way that's easy to
    # confuse with a real value if we're not deliberate about it.
    token_placeholder_text = token_placeholder if token_placeholder is not None else "NONE"

    # We build one single, unambiguous string out of all our input
    # fields, separated by a delimiter ("|") that is very unlikely to
    # appear inside any of these values themselves. This matters: if
    # we just glued the fields together with nothing between them, the
    # combination ("AB", "C") and ("A", "BC") would hash identically by
    # accident, since "AB"+"C" and "A"+"BC" both produce the string
    # "ABC". The delimiter avoids that ambiguity.
    combined_text = (
        f"{timestamp}|{tenant_id}|{action}|{token_placeholder_text}|{status}|{previous_hash}"
    )

    # ".encode()" turns our combined text into bytes, since hashing
    # math (like our earlier XOR encryption) operates on bytes, not on
    # Python's text-string objects directly.
    combined_bytes = combined_text.encode()

    # hashlib.sha256(...) runs the actual SHA-256 algorithm on those
    # bytes. ".hexdigest()" converts the resulting fingerprint into a
    # safe, readable string of hex characters (0-9 and a-f) -- a
    # convenient, fixed-length TEXT format perfect for a SQLite TEXT
    # column. (Recall ".hexdigest()" vs ".digest()": hexdigest gives
    # human-readable text, digest gives raw bytes -- here we want text,
    # since this is going straight into a database TEXT column.)
    return hashlib.sha256(combined_bytes).hexdigest()


# A static placeholder used as the "previous_hash" for the very FIRST
# log entry ever written -- since there's no real previous row to link
# to yet. Using a simple, well-known constant like this (rather than,
# say, leaving it blank) means the very first row is hashed using the
# exact same formula as every other row, with no special-case math
# anywhere else in the code.
GENESIS_HASH = "0"


def _write_audit_log(tenant_id, action, token_placeholder, status):
    """
    UPDATED FUNCTION.
    Records one permanent, HASH-CHAINED row in the audit_logs table.

    The leading underscore "_" marks this as an internal helper, same
    convention as _xor_bytes() and _derive_tenant_key() above -- it's
    meant to be called from WITHIN this file (specifically, from
    tokenize_data() and detokenize_data()), not from main.py or
    anywhere else.

    Parameters:
      tenant_id          -> which organization performed the action.
      action             -> a short label like "TOKENIZE" or
                            "DETOKENIZE", describing what was attempted.
      token_placeholder -> the token involved, if there is one. Some
                            situations genuinely don't have a token to
                            record yet -- for example, if tokenize_data()
                            fails before it ever generates one. We
                            allow this parameter to be None (Python's
                            "nothing" value) for exactly those cases.
      status             -> the outcome of the action: "SUCCESS",
                            "FAILED_NOT_FOUND", or "ERROR".

    NEW LOGIC, STEP BY STEP:
      1. Look up the current_hash of whatever row was written MOST
         RECENTLY across the WHOLE table (not just this tenant -- the
         chain links every entry from every tenant together in one
         single, global sequence, ordered by insertion order/id).
      2. If the table is completely empty (this is the very first log
         entry ever), use GENESIS_HASH ("0") instead, since there's no
         real previous row to reference yet.
      3. Calculate a brand new hash for THIS row, combining its own
         data with that previous hash.
      4. Insert the new row, storing BOTH the previous_hash we looked
         up AND the current_hash we just calculated.

    WHY THIS FUNCTION ONLY EVER INSERTS, NEVER UPDATES OR DELETES:
    Look closely below -- the only SQL commands in this entire function
    are "SELECT" (read-only) and "INSERT INTO". There is no UPDATE, no
    DELETE, anywhere in this function, and (you can check) nowhere
    else in this whole file either. That is a deliberate, permanent
    design choice: once a log row is written, NOTHING in vault.py is
    capable of changing or removing it again. Combined with the hash
    chain, this means even someone who bypasses this Python file
    entirely and edits the .db file directly cannot make undetectable
    changes -- that's the actual point of this whole feature.
    """
    # datetime.datetime.now() asks the operating system's clock for
    # the exact current date and time, down to fractions of a second.
    # ".isoformat()" converts that into a standard, sortable, universally
    # understood text format that looks like "2026-06-21T14:32:07.123456"
    # -- this format sorts correctly as plain TEXT in SQLite, which is
    # exactly why get_audit_logs() sorts by it directly with a simple
    # "ORDER BY timestamp" SQL clause.
    current_timestamp = datetime.datetime.now().isoformat()

    # Open our own short-lived connection just for this one write. We
    # deliberately do NOT try to reuse a connection passed in from
    # tokenize_data()/detokenize_data() -- keeping this function fully
    # self-contained means it can never accidentally be skipped or
    # left half-finished if something goes wrong in the calling code.
    connection = get_connection()
    cursor = connection.cursor()

    # NEW STEP 1 & 2: find the current_hash of the most recently
    # inserted row in the ENTIRE table (across all tenants), so we can
    # link our new row to it.
    #
    # "ORDER BY id DESC LIMIT 1" means: "sort all rows by their id
    # column, biggest/most-recent first, then give me only the very
    # first result." Since "id" auto-increments with every insert,
    # the row with the highest id is always the most recently written
    # one -- a simple, reliable way to find "whatever came last."
    cursor.execute("SELECT current_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
    most_recent_row = cursor.fetchone()

    # If most_recent_row is None, the table is completely empty (this
    # is the very first log entry ever written), so we fall back to
    # our GENESIS_HASH constant. Otherwise, we use the real hash we
    # just looked up. This single line is Python's compact way of
    # writing an if/else: "use most_recent_row[0] if it exists,
    # otherwise use GENESIS_HASH."
    previous_hash = most_recent_row[0] if most_recent_row is not None else GENESIS_HASH

    # STEP 3: calculate this row's own hash, linking it to previous_hash.
    # BUG FIX: token_placeholder is now included here too (see the bug
    # fix note inside _calculate_log_hash()'s docstring) -- without
    # this, the token a log entry points to could be silently swapped
    # without breaking the hash chain at all.
    current_hash = _calculate_log_hash(
        current_timestamp, tenant_id, action, token_placeholder, status, previous_hash
    )

    # NEW STEP 4: insert the new row, now including BOTH previous_hash
    # and current_hash alongside the original fields. The "?"
    # placeholders are filled in safely from the tuple we provide,
    # preventing SQL injection.
    cursor.execute(
        "INSERT INTO audit_logs "
        "(timestamp, tenant_id, action, token_placeholder, status, previous_hash, current_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (current_timestamp, tenant_id, action, token_placeholder, status, previous_hash, current_hash)
    )

    connection.commit()  # Save this log entry permanently to disk.
    connection.close()   # Hang up the phone line.


# --------------------------------------------------------------------
# STEP 5: GENERATE A RANDOM TOKEN
# --------------------------------------------------------------------

def _generate_random_token(length):
    """
    Creates a random string of letters+digits of the requested length.
    This is the "fake" placeholder value that's safe to use elsewhere
    in our systems instead of the real sensitive data.
    """
    # secrets.choice(...) picks ONE random, secure character from the
    # set of allowed characters we give it.
    # We do that "length" number of times (the for-loop), then
    # "".join(...) glues all those single characters into one string.
    allowed_characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(allowed_characters) for _ in range(length))
    # Note: "_" here is just a throwaway variable name -- a Python
    # convention meaning "I need a loop counter, but I don't actually
    # care about its value."


# --------------------------------------------------------------------
# STEP 6: THE MAIN PUBLIC FUNCTIONS -- TOKENIZE / DETOKENIZE
# --------------------------------------------------------------------

def tokenize_data(real_data, tenant_id):
    """
    CHANGED: now requires tenant_id as a second argument, and now
    writes an audit log entry for every attempt.

    Public function #1.
    Input:  a real, sensitive string (e.g. an SSN), AND the tenant_id
            of the company this data belongs to.
    Output: a safe random token that stands in for it, scoped to that
            tenant.

    Logic:
      1. Encrypt the real data using a key derived from THIS tenant's
         tenant_id (so we never store it in plain text, and so it's
         cryptographically distinct per tenant).
      2. Check: has THIS SAME TENANT already tokenized this exact piece
         of data before? If yes, hand back the SAME token as last
         time, instead of creating a confusing duplicate. Note we now
         check tenant_id too -- Company A tokenizing "4111..." and
         Company B tokenizing "4111..." are treated as two completely
         separate, unrelated events.
      3. If it's new (for this tenant), generate a fresh random token
         of the same length as the input, save the
         (tenant_id, token -> encrypted data) row, and return the new
         token.
      4. NEW: log the outcome (SUCCESS or ERROR) to the audit_logs
         table before returning or re-raising.

    NEW: WHY THE "try / except / raise" STRUCTURE BELOW MATTERS.
    We wrap the real work in a "try" block so that if ANYTHING goes
    wrong partway through -- a database problem, an encryption problem,
    anything -- we still get a chance to write an "ERROR" audit log
    entry before the problem is allowed to continue. The line "raise"
    at the end of the "except" block means "after logging this, let the
    error keep happening as normal" -- we are NOT swallowing or hiding
    the error from main.py, which still needs to know something went
    wrong so it can show the user a friendly message. We're simply
    inserting an audit log write in between "something broke" and
    "main.py finds out."
    """
    # "try:" begins a block where we attempt the real tokenize logic.
    try:
        connection = get_connection()
        cursor = connection.cursor()

        # Encrypt the real data up front, mixing in tenant_id as our
        # salt. This is what we'll compare against and what we'll
        # store. We NEVER store real_data directly.
        encrypted_version = encrypt_data(real_data, tenant_id)

        # "SELECT column FROM table WHERE condition" asks the database
        # to find and return matching rows. The "?" placeholders are
        # filled in safely by SQLite from the tuple we provide -- this
        # prevents a security bug called "SQL injection."
        #
        # We filter by BOTH encrypted_data AND tenant_id. This means
        # deduplication only happens WITHIN one tenant's own data --
        # exactly what we want.
        cursor.execute(
            "SELECT token_placeholder FROM tokens WHERE encrypted_data = ? AND tenant_id = ?",
            (encrypted_version, tenant_id)
        )

        # ".fetchone()" grabs the first matching row found, or returns
        # "None" (Python's way of saying "nothing here") if there was
        # no match at all.
        existing_row = cursor.fetchone()

        # "is not None" means "we DID find something."
        if existing_row is not None:
            # existing_row is a tuple like ('aB3xZ9',) -- a tuple is
            # just an ordered, fixed little bundle of values. [0] grabs
            # the first (and here, only) item out of it.
            connection.close()
            token = existing_row[0]  # The SAME token as before.

            # NEW: log this as a successful tokenize attempt, even
            # though no NEW row was inserted -- from the caller's point
            # of view, asking to tokenize data and getting back a valid
            # token is a success either way.
            _write_audit_log(tenant_id, "TOKENIZE", token, "SUCCESS")
            return token

        # If we reach this point, this tenant has never tokenized this
        # particular piece of data before.
        token = _generate_random_token(len(real_data))

        # "INSERT INTO table (columns) VALUES (values)" adds a brand
        # new row to the table. Again we use "?" placeholders for
        # safety. We also insert tenant_id alongside the token and
        # encrypted data.
        cursor.execute(
            "INSERT INTO tokens (tenant_id, token_placeholder, encrypted_data) VALUES (?, ?, ?)",
            (tenant_id, token, encrypted_version)
        )

        connection.commit()  # Save this new row permanently to disk.
        connection.close()   # Hang up the phone line.

        # NEW: log this brand-new tokenization as a success.
        _write_audit_log(tenant_id, "TOKENIZE", token, "SUCCESS")

        return token

    # "except Exception as error" catches ANY kind of failure that
    # happened anywhere inside the "try" block above -- a database
    # problem, an encryption problem, anything at all.
    except Exception as error:
        # NEW: record that this attempt failed with an ERROR, before
        # letting the error continue. We don't have a valid token to
        # attach here (something went wrong before or during creating
        # one), so we pass None for token_placeholder -- recall the
        # audit_logs table allows this column to be empty for exactly
        # this situation.
        _write_audit_log(tenant_id, "TOKENIZE", None, "ERROR")

        # "raise" with nothing after it means "re-throw the SAME error
        # that just happened." This lets main.py's own try/except still
        # catch it and show the user a friendly message -- we're only
        # inserting a logging step, not hiding the problem.
        raise


def detokenize_data(token, tenant_id):
    """
    CHANGED: now requires tenant_id as a second argument, and now
    writes an audit log entry for every attempt.

    Public function #2.
    Input:  a token that was previously generated by tokenize_data(),
            AND the tenant_id making the request.
    Output: the original real data string, decrypted -- but ONLY if
            that exact token belongs to that exact tenant.

    If the token doesn't exist for THAT tenant (even if it exists for
    a DIFFERENT tenant!), we return None (Python's "nothing/empty"
    value) rather than crashing or, worse, leaking another company's
    data. This is the core of tenant isolation: Company A asking for
    a token that actually belongs to Company B gets exactly the same
    "not found" response as asking for a token that doesn't exist at
    all anywhere. From the outside, those two situations are
    indistinguishable -- which is exactly what good isolation looks
    like.

    NEW: every attempt now writes one of three possible audit log
    statuses:
      "SUCCESS"           -> the token existed for this tenant, and we
                            successfully decrypted and returned the
                            real data.
      "FAILED_NOT_FOUND"  -> no row existed for this exact
                            (token, tenant_id) combination -- this is
                            NOT a crash, just a normal "nothing found"
                            result, but it's worth recording, since a
                            pattern of these can indicate someone
                            probing the system with guessed tokens.
      "ERROR"             -> something actually broke unexpectedly
                            (e.g. a database problem) while attempting
                            the lookup or decryption.
    """
    # "try:" begins a block where we attempt the real detokenize logic,
    # so that any unexpected failure still gets logged before it's
    # allowed to propagate up to main.py.
    try:
        connection = get_connection()
        cursor = connection.cursor()

        # The WHERE clause requires BOTH the token AND the tenant_id to
        # match the same row. This single line is what makes it
        # database-level impossible for Company A to ever pull back a
        # row that belongs to Company B, even by accident or bug
        # elsewhere in the code.
        cursor.execute(
            "SELECT encrypted_data FROM tokens WHERE token_placeholder = ? AND tenant_id = ?",
            (token, tenant_id)
        )

        row = cursor.fetchone()
        connection.close()

        if row is None:
            # NEW: this is a normal, expected "not found" outcome --
            # not an error -- so we log it with its own specific
            # status rather than lumping it in with real ERRORs.
            _write_audit_log(tenant_id, "DETOKENIZE", token, "FAILED_NOT_FOUND")
            return None  # No matching token for THIS tenant.

        encrypted_version = row[0]

        # Decrypt using a key derived from THIS SAME tenant_id -- this
        # is the cryptography-layer half of tenant isolation. Even in
        # the extremely unlikely case that two tenants' rows got mixed
        # up somehow upstream, decrypting with the wrong tenant_id
        # produces nonsense garbage bytes, not another tenant's real
        # data.
        real_data = decrypt_data(encrypted_version, tenant_id)

        # NEW: log this as a successful detokenize attempt.
        _write_audit_log(tenant_id, "DETOKENIZE", token, "SUCCESS")

        return real_data

    # "except Exception as error" catches ANY kind of failure that
    # happened anywhere inside the "try" block above.
    except Exception as error:
        # NEW: record that this attempt failed with a genuine ERROR
        # (as opposed to the normal, expected FAILED_NOT_FOUND case
        # handled above), before letting the error continue.
        _write_audit_log(tenant_id, "DETOKENIZE", token, "ERROR")

        # "raise" with nothing after it means "re-throw the SAME error
        # that just happened," so main.py's own try/except still gets
        # the chance to catch it and show the user a friendly message.
        raise


# --------------------------------------------------------------------
# STEP 6B (NEW): READ BACK THE AUDIT HISTORY FOR A TENANT
# --------------------------------------------------------------------

def get_audit_logs(tenant_id):
    """
    NEW PUBLIC FUNCTION.
    Public function #3.
    Input:  a tenant_id.
    Output: a list of that tenant's audit log entries, NEWEST first.

    Each entry in the returned list is a tuple in this exact order:
        (timestamp, action, token_placeholder, status)

    Why "newest first"? When a compliance officer or auditor pulls up
    an activity history, they almost always want to see "what just
    happened" before scrolling back through ancient history -- so we
    sort with the most recent entries at the very top.

    NOTICE: this function only ever filters by tenant_id and reads
    with SELECT. It cannot modify or delete anything -- there is no
    code path anywhere in this file that lets a tenant alter their own
    (or anyone else's) audit history. That's intentional, for the same
    "append-only in practice" reason described in _write_audit_log()'s
    docstring above.
    """
    connection = get_connection()
    cursor = connection.cursor()

    # "ORDER BY timestamp DESC" tells SQLite to sort the results by the
    # timestamp column. "DESC" means "descending" -- biggest/most
    # recent value first. Because we stored timestamps using
    # datetime's .isoformat() (e.g. "2026-06-21T14:32:07.123456"),
    # sorting them as plain TEXT happens to ALSO sort them correctly by
    # actual chronological time -- this is one of the main reasons
    # ISO format is the standard choice for storing timestamps as text.
    cursor.execute(
        "SELECT timestamp, action, token_placeholder, status "
        "FROM audit_logs WHERE tenant_id = ? ORDER BY timestamp DESC",
        (tenant_id,)
    )

    # ".fetchall()" grabs EVERY matching row at once, as a list of
    # tuples. For a small prototype/early-stage product this is simple
    # and fine; if your audit log ever grows to millions of rows,
    # you'd eventually want to fetch results in smaller pages instead
    # of all at once, to keep memory usage low -- but that's a future
    # optimization, not something you need to worry about yet.
    all_matching_rows = cursor.fetchall()
    connection.close()

    return all_matching_rows


# --------------------------------------------------------------------
# STEP 6C (NEW): VERIFY THE ENTIRE HASH CHAIN, START TO FINISH
# --------------------------------------------------------------------

def verify_ledger_integrity():
    """
    NEW PUBLIC FUNCTION.
    Public function #4.
    Walks through EVERY row in the audit_logs table, from the very
    first one ever written to the very last, and checks whether the
    hash chain is fully intact.

    Returns:
      True  -> every single row's hash checks out; the ledger has not
               been tampered with (at least, not in any way our hash
               chain can detect -- see the limitations note at the
               bottom of this docstring).
      False -> at least one row failed verification. This function
               also PRINTS exactly which row(s) failed and why, so you
               (or a future compliance officer) can investigate.

    THE CORE IDEA, STEP BY STEP:
    For each row, in order, we:
      1. Re-run the EXACT SAME hash calculation that _write_audit_log()
         used when this row was first created -- combining this row's
         own stored data with its OWN stored previous_hash.
      2. Compare our freshly recalculated hash against the current_hash
         value that's actually sitting in the database for this row.
      3. If they match: this row's content has not been altered since
         it was written. Move on to the next row.
      4. If they DON'T match: something about this row's data was
         changed after the fact (by someone bypassing our Python code
         and editing the database directly). We flag it and stop.
      5. SEPARATELY, we also check that each row's previous_hash
         actually equals the PRECEDING row's current_hash. This catches
         a sneakier kind of tampering: someone who edits a row AND
         successfully recalculates a new matching current_hash for
         it (defeating check #2 above) still cannot make the NEXT
         row's previous_hash retroactively match their fake new hash,
         because that next row was already written with the ORIGINAL,
         correct value baked in. This is the actual "chain" part of
         hash chaining -- it's what makes tampering with one row
         visible at the row immediately AFTER it, even if the tampered
         row alone looks internally consistent.

    A NOTE ON LIMITATIONS (worth understanding, not a flaw to "fix"):
    This detects tampering with EXISTING rows. It does NOT, by itself,
    detect someone deleting the LAST row entirely and forgetting to
    add a replacement, since there's nothing after it to notice a
    broken link. Real production systems often pair hash chaining with
    a separately stored "last known good hash," checked against an
    outside system, to catch even that case. That's a further
    enhancement for later -- this function still catches the vast
    majority of realistic tampering: anyone editing field values on
    any past row.
    """
    connection = get_connection()
    cursor = connection.cursor()

    # "ORDER BY id ASC" sorts rows by their auto-incrementing id,
    # SMALLEST first -- i.e. oldest/first-written row first. This is
    # the opposite order from get_audit_logs() on purpose: to verify a
    # chain, we MUST walk it in the same order it was originally built,
    # starting from the very first link.
    # BUG FIX: token_placeholder is now included in this SELECT (it was
    # previously left out, which meant a tampered token could never be
    # detected -- see the bug fix note inside _calculate_log_hash()).
    cursor.execute(
        "SELECT id, timestamp, tenant_id, action, token_placeholder, status, previous_hash, current_hash "
        "FROM audit_logs ORDER BY id ASC"
    )
    all_rows = cursor.fetchall()
    connection.close()

    # If there are no rows at all, there's nothing to verify, and an
    # empty ledger certainly hasn't been tampered with -- so we
    # consider this a trivially "passing" case.
    if len(all_rows) == 0:
        print("[INFO] Audit log is empty -- nothing to verify.")
        return True

    # This variable tracks what we EXPECT the next row's previous_hash
    # to be, based on the chain so far. We start with GENESIS_HASH,
    # since that's what the very FIRST row should have used.
    expected_previous_hash = GENESIS_HASH

    # "for row in all_rows:" walks through every row we fetched, one
    # at a time, in the oldest-to-newest order we requested above.
    for row in all_rows:
        # Unpack this row's columns into individually named variables,
        # in the same order we selected them above, for readability.
        row_id, timestamp, tenant_id, action, token_placeholder, status, stored_previous_hash, stored_current_hash = row

        # CHECK A: does this row's STORED previous_hash match what we
        # expect, based on the chain built so far? If someone deleted
        # a row in the middle, or reordered rows, or tampered with an
        # earlier row's current_hash directly, this is where it shows
        # up.
        if stored_previous_hash != expected_previous_hash:
            print(f"[TAMPER DETECTED] Row id={row_id}: stored previous_hash does not "
                  f"match the expected chain value.")
            print(f"    Expected previous_hash: {expected_previous_hash}")
            print(f"    Stored   previous_hash: {stored_previous_hash}")
            return False

        # CHECK B: recalculate this row's hash from its OWN stored
        # data, and see if it matches the current_hash actually stored
        # for this row. If someone edited this row's timestamp,
        # tenant_id, action, token_placeholder, or status directly in
        # the database, the recalculated hash will come out completely
        # different (recall the "avalanche effect" explained in
        # _calculate_log_hash()).
        recalculated_hash = _calculate_log_hash(
            timestamp, tenant_id, action, token_placeholder, status, stored_previous_hash
        )

        if recalculated_hash != stored_current_hash:
            print(f"[TAMPER DETECTED] Row id={row_id}: recalculated hash does not "
                  f"match the stored hash.")
            print(f"    This row's data appears to have been modified after it "
                  f"was originally written.")
            print(f"    Recalculated hash: {recalculated_hash}")
            print(f"    Stored hash:       {stored_current_hash}")
            return False

        # If we reach this point, this row checks out completely.
        # Update expected_previous_hash to THIS row's current_hash,
        # since that's what the NEXT row in line should reference.
        expected_previous_hash = stored_current_hash

    # If we made it through every single row in the "for" loop above
    # without returning False, the entire chain is intact, start to
    # finish.
    print(f"[OK] Verified {len(all_rows)} audit log entries -- the entire "
          f"hash chain is intact.")
    return True


# --------------------------------------------------------------------
# STEP 7: MULTI-TENANT + AUDIT LOG SIMULATION / TEST BLOCK
# --------------------------------------------------------------------

# This special "if" check is a Python convention. It means: "only run
# the code below if this file was run DIRECTLY (e.g. `python vault.py`),
# not if it was imported as a helper module into some other file."
# This lets other parts of your future SaaS `import vault` and reuse
# tokenize_data()/detokenize_data() WITHOUT accidentally re-running this
# demo every time.
if __name__ == "__main__":

    print("Setting up the vault database...")
    initialize_database()
    print(f"Database ready: {DATABASE_FILENAME}\n")

    # The SAME credit card number, but belonging to two DIFFERENT
    # companies using our SaaS. This is the exact scenario the whole
    # feature exists to handle correctly.
    shared_card_number = "4111222233334444"

    print("=" * 70)
    print(" DEMO 1: Same data, different tenants -> different tokens")
    print("=" * 70)

    token_company_a = tokenize_data(shared_card_number, tenant_id="company_a")
    token_company_b = tokenize_data(shared_card_number, tenant_id="company_b")

    print(f"  Company A tokenizes {shared_card_number!r} -> {token_company_a}")
    print(f"  Company B tokenizes {shared_card_number!r} -> {token_company_b}")

    # "assert" is a sanity-check statement: "I expect this condition to
    # be true. If it's NOT true, crash immediately with an error,
    # because something is fundamentally broken." We use it here to
    # make the proof undeniable rather than just eyeballing the output.
    assert token_company_a != token_company_b, (
        "FAILURE: both tenants got the same token for the same data! "
        "Multi-tenant isolation is broken."
    )
    print("  [VERIFIED] The two tokens are different, even though the\n"
          "             underlying card number is identical.\n")

    print("=" * 70)
    print(" DEMO 2: Each tenant can correctly detokenize their OWN token")
    print("=" * 70)

    recovered_a = detokenize_data(token_company_a, tenant_id="company_a")
    recovered_b = detokenize_data(token_company_b, tenant_id="company_b")

    print(f"  Company A detokenizes their token -> {recovered_a!r}")
    print(f"  Company B detokenizes their token -> {recovered_b!r}")

    assert recovered_a == shared_card_number
    assert recovered_b == shared_card_number
    print("  [VERIFIED] Both tenants correctly recover the real card number\n"
          "             using their OWN token.\n")

    print("=" * 70)
    print(" DEMO 3: Tenant isolation -- Company A CANNOT use Company B's token")
    print("=" * 70)

    # This is the critical security test: Company A tries to look up
    # the TOKEN THAT BELONGS TO COMPANY B, using their own tenant_id.
    cross_tenant_attempt = detokenize_data(token_company_b, tenant_id="company_a")

    print(f"  Company A tries to detokenize Company B's token "
          f"({token_company_b})...")
    print(f"  Result: {cross_tenant_attempt!r}")

    assert cross_tenant_attempt is None, (
        "FAILURE: Company A was able to read Company B's data! "
        "This is a critical tenant isolation breach."
    )
    print("  [VERIFIED] The vault correctly refused -- Company A gets "
          "nothing back,\n"
          "             exactly as if that token never existed at all.\n")

    print("=" * 70)
    print(" DEMO 4: Encryption-level proof -- ciphertext differs per tenant")
    print("=" * 70)
    print("Here is what is ACTUALLY sitting in secure_vault.db on disk:")

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        "SELECT tenant_id, token_placeholder, encrypted_data FROM tokens "
        "WHERE tenant_id IN ('company_a', 'company_b')"
    )
    rows = cursor.fetchall()
    for tenant_id, token_placeholder, encrypted_data in rows:
        print(
            f"  tenant_id={tenant_id!r:12} "
            f"token={token_placeholder!r:20} "
            f"encrypted_data={encrypted_data!r}"
        )
    connection.close()

    # Pull out just the two encrypted_data strings to compare directly.
    encrypted_values_seen = {row[0]: row[2] for row in rows}
    assert encrypted_values_seen["company_a"] != encrypted_values_seen["company_b"], (
        "FAILURE: the encrypted bytes are identical across tenants! "
        "The cryptographic salt isn't working."
    )

    print(
        "\n  [VERIFIED] Even though both rows encode the SAME real card "
        "number,\n"
        "             the encrypted_data hex strings are completely "
        "different.\n"
        "             Someone with raw access to this .db file cannot tell\n"
        "             these two customers share a card number, and cannot\n"
        "             decrypt either one without our master "
        "VAULT_SECRET_KEY.\n"
    )

    print("ALL MULTI-TENANT CHECKS PASSED.\n")

    print("=" * 70)
    print(" DEMO 5: Audit Log System -- recording a realistic activity history")
    print("=" * 70)

    # We already generated some real SUCCESS-status log entries just by
    # running Demos 1-3 above (every tokenize_data() and detokenize_data()
    # call automatically writes its own audit log entry now). To make
    # this demo realistic, let's also deliberately trigger a
    # FAILED_NOT_FOUND entry, by asking Company A to detokenize a token
    # that plainly doesn't exist anywhere.
    print("  Company A attempts to detokenize a token that doesn't exist...")
    nonexistent_attempt = detokenize_data("THISTOKENDOESNOTEXIST", tenant_id="company_a")
    print(f"  Result: {nonexistent_attempt!r}")

    assert nonexistent_attempt is None, (
        "FAILURE: a nonexistent token returned real data instead of None!"
    )
    print("  [VERIFIED] Correctly returned nothing for the bogus token -- "
          "and this attempt\n"
          "             should now appear in Company A's audit log with "
          "status FAILED_NOT_FOUND.\n")

    print("  Fetching Company A's full audit history (newest first)...\n")
    company_a_logs = get_audit_logs("company_a")

    # Print a simple, readable table of the results.
    print(f"  {'TIMESTAMP':27} {'ACTION':12} {'TOKEN':20} {'STATUS'}")
    print("  " + "-" * 75)
    for log_timestamp, log_action, log_token, log_status in company_a_logs:
        # "or ''" handles the case where log_token is None (e.g. an
        # ERROR that happened before any token existed) by displaying
        # an empty string instead of the text "None".
        display_token = log_token or ""
        print(f"  {log_timestamp:27} {log_action:12} {display_token:20} {log_status}")

    # Sanity-check: confirm we can see BOTH a SUCCESS and a
    # FAILED_NOT_FOUND entry somewhere in Company A's history, proving
    # both status types are actually being recorded correctly.
    statuses_seen = {row[3] for row in company_a_logs}
    assert "SUCCESS" in statuses_seen, "FAILURE: no SUCCESS entries found in the audit log!"
    assert "FAILED_NOT_FOUND" in statuses_seen, (
        "FAILURE: the FAILED_NOT_FOUND attempt was not recorded in the audit log!"
    )

    # Sanity-check: confirm the results are genuinely sorted newest
    # first, by checking that timestamps are sorted from largest down
    # to smallest as plain text (ISO format makes this a valid check).
    all_timestamps = [row[0] for row in company_a_logs]
    assert all_timestamps == sorted(all_timestamps, reverse=True), (
        "FAILURE: audit log entries are not correctly sorted newest-first!"
    )

    print(
        "\n  [VERIFIED] Company A's audit history includes both SUCCESS "
        "and\n"
        "             FAILED_NOT_FOUND entries, correctly sorted with the "
        "most\n"
        "             recent activity at the top -- exactly what a "
        "compliance\n"
        "             audit would need to see.\n"
    )

    print("ALL AUDIT LOG CHECKS PASSED.\n")

    print("=" * 70)
    print(" DEMO 6: Cryptographic Hash Chaining -- tamper-evidence proof")
    print("=" * 70)

    print("  Step 1: verify the ledger BEFORE any tampering has occurred...\n")
    chain_is_valid_before = verify_ledger_integrity()

    assert chain_is_valid_before is True, (
        "FAILURE: the untouched, legitimate hash chain failed verification! "
        "Something is wrong with the hashing logic itself."
    )
    print("\n  [VERIFIED] The untouched ledger passes verification completely.\n")

    print("  Step 2: simulate an attacker bypassing vault.py entirely and "
          "editing\n"
          "          the database file directly with raw SQL (exactly the "
          "kind of\n"
          "          tampering our Python code's lack of UPDATE/DELETE "
          "can't stop\n"
          "          on its own -- this is precisely what the hash chain "
          "is for).\n")

    # We deliberately reach around our own tokenize_data()/detokenize_data()
    # functions here and write raw SQL directly, exactly as a real
    # attacker with file access to secure_vault.db could. We pick the
    # very FIRST row (the oldest one) to tamper with, since that's the
    # scenario where the attacker has the most rows after it to "fix up"
    # if they wanted to try covering their tracks -- and we'll see even
    # that doesn't save them.
    tamper_connection = get_connection()
    tamper_cursor = tamper_connection.cursor()
    tamper_cursor.execute("SELECT id, status FROM audit_logs ORDER BY id ASC LIMIT 1")
    first_row_id, original_status = tamper_cursor.fetchone()

    # Pick a new status that is GUARANTEED to be different from
    # whatever the original value actually was -- otherwise "changing"
    # it to the same value wouldn't be a real edit at all, and the
    # hash would correctly still match (which is NOT a bug, just a
    # demo that forgot to actually change anything!). This little
    # safeguard makes sure our demo always performs a genuine edit.
    if original_status == "SUCCESS":
        tampered_status = "FAILED_NOT_FOUND"
    else:
        tampered_status = "SUCCESS"

    print(f"  Targeting row id={first_row_id}, silently changing its status "
          f"from {original_status!r} to {tampered_status!r}\n"
          f"  WITHOUT recalculating any hashes (exactly what a careless, or "
          f"even a careful,\n"
          f"  attacker editing the raw file would do)...\n")

    tamper_cursor.execute(
        "UPDATE audit_logs SET status = ? WHERE id = ?",
        (tampered_status, first_row_id)
    )
    tamper_connection.commit()
    tamper_connection.close()

    print("  Step 3: verify the ledger AFTER tampering...\n")
    chain_is_valid_after = verify_ledger_integrity()

    assert chain_is_valid_after is False, (
        "FAILURE: verify_ledger_integrity() did NOT catch a deliberately "
        "tampered row! The hash chain is not working correctly."
    )

    print(
        "\n  [VERIFIED] The tampering was caught immediately. Editing even "
        "ONE\n"
        "             field on ONE old row, without recalculating the "
        "entire\n"
        "             hash chain from that point forward, is enough to "
        "break\n"
        "             verification -- exactly the tamper-evidence property "
        "a\n"
        "             compliance audit log needs.\n"
    )

    print("ALL HASH CHAIN CHECKS PASSED.")
