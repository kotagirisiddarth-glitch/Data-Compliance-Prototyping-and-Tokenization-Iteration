"""
main.py
-------
This is the "front door" of our SaaS -- the program a person actually
runs and interacts with. It does NOT contain any encryption or database
logic itself; all of that heavy lifting already lives in vault.py.

This file's only job is to:
  1. Ask the user to "log in" with an Organization ID, right at boot.
  2. Show a menu, with the active organization clearly displayed.
  3. Ask the user what they want to do.
  4. Call the right function from vault.py, using the active org ID.
  5. Show the result, or a friendly error if something went wrong.
  6. Loop back to the menu, forever, until the user chooses to exit.

This separation -- "vault.py handles security, main.py handles the
user interface" -- is a real software design principle called
"separation of concerns." It means if you later swap the CLI for a
website or an API, you can reuse vault.py completely untouched.

=====================================================================
 UPDATED: "SESSION" STYLE LOGIN, INSTEAD OF ASKING EVERY TIME
=====================================================================
Previously, this file asked "which tenant are you?" freshly on every
single Tokenize/Detokenize action, which got repetitive fast. Now we
ask ONCE at startup (like logging into an account), remember the
answer in a variable for the rest of the program's run, show it at
the top of the menu so it's always clear which company's vault you're
working in, and offer a menu option to deliberately switch to a
different organization without restarting the whole program.

IMPORTANT REAL-WORLD NOTE (same caveat as before, still true): typing
an Organization ID into a text box is NOT real authentication -- there
is no password, no verification, nothing stopping someone from typing
"company_b" and instantly acting as Company B. This is fine for you,
alone, testing on your own laptop. Before this becomes a real product
serving real companies, "logging in" must be backed by a verified
credential (a password, an API key, a proper login system) -- not a
free-typed field that simply trusts whatever the user claims. We'll
build that properly later; for now, keep this limitation in mind.
"""

# "from vault import X, Y" means: "go open the file vault.py that sits
# in this same folder, and pull out specifically these names so I can
# use them directly here." This only works because vault.py is
# sitting right next to main.py.
#
# Note: importing vault.py this way WILL run any top-level code in that
# file (like reading the VAULT_SECRET_KEY environment variable), but it
# will NOT run vault.py's own simulation block at the bottom, because
# that block is protected by an `if __name__ == "__main__":` guard.
# That guard exists for exactly this situation.
from vault import tokenize_data, detokenize_data, initialize_database


def ask_for_organization_id(prompt_text):
    """
    Asks the user to type an Organization ID and returns a cleaned-up
    version of it.

    "prompt_text" is a PARAMETER -- a placeholder name that lets this
    one function be reused for slightly different wording in different
    situations (the very first login prompt vs. the "switch org" prompt
    later use different wording, but both need the exact same cleanup
    logic). Whatever text string we hand this function when we CALL it
    is what gets displayed.

    We loop with "while True" here so that if the user just presses
    Enter without typing anything, we politely ask again instead of
    silently accepting a blank Organization ID and causing confusing
    problems later.
    """
    # "while True:" creates a loop that repeats FOREVER, until
    # something inside it explicitly stops it (here, with "return",
    # which both gives back a value AND immediately exits the
    # function/loop in one step).
    while True:
        # "input(...)" pauses the program, displays the given prompt
        # text, and waits for the user to type something and press
        # Enter, handing back whatever they typed as a string.
        raw_input_value = input(prompt_text)

        # ".strip()" removes accidental leading/trailing spaces, so
        # " company_a " and "company_a" are treated identically.
        cleaned_value = raw_input_value.strip()

        # ".lower()" converts all letters to lowercase. We do this so
        # "Company_A", "COMPANY_A", and "company_a" are all treated as
        # the SAME organization, instead of accidentally becoming
        # three different tenants just because of how someone happened
        # to type it that day.
        cleaned_value = cleaned_value.lower()

        # "if not cleaned_value:" means "if this string is empty."
        if not cleaned_value:
            print("[!] Organization ID cannot be blank. Please try again.\n")
            # "continue" skips the rest of this loop pass and jumps
            # straight back up to "while True:" to ask again.
            continue

        # As soon as we have a valid, non-blank value, hand it back to
        # whoever called this function, and stop looping.
        return cleaned_value


def print_banner():
    """
    Prints a stylized ASCII text banner. "ASCII art" just means text
    characters arranged to look like a picture/logo -- no image file
    needed, which keeps this program lightweight and dependency-free.

    Triple-quoted strings (three quote-marks, then text, then three
    more quote-marks) let us write a string that spans multiple lines
    exactly as it appears, including all the spacing -- perfect for
    ASCII art.
    """
    banner = """
   ____ ___  __  __ ____  _     ___    _    _   _  ____ ____    ____    _    _    _    ____
  / ___/ _ \\|  \\/  |  _ \\| |   |_ _|  / \\  | \\ | |/ ___/ ___|  / ___|  / \\  / \\  / \\  / ___|
 | |  | | | | |\\/| | |_) | |    | |  / _ \\ |  \\| | |   | |     \\___ \\ / _ \\ \\_ \\\\\\/ _ \\\\___ \\
 | |__| |_| | |  | |  __/| |___ | | / ___ \\| |\\  | |___| |___   ___) / ___ \\  / / ___ \\___) |
  \\____\\___/|_|  |_|_|   |_____|___/_/   \\_\\_| \\_|\\____\\____| |____/_/   \\_\\/_/_/   \\_\\____/

                      C O N T R O L   P A N E L   --  v2.0
"""
    # "print(...)" displays text in the terminal window.
    print(banner)


def print_menu(active_tenant_id):
    """
    Prints the list of numbered choices the user can pick from, PLUS
    (new) a clear banner line showing which organization is currently
    active. "active_tenant_id" is a parameter -- this function doesn't
    know or care WHERE that value came from, it just displays whatever
    is handed to it. That's good design: this function has exactly one
    job, displaying the menu, and doesn't need to know about logins,
    sessions, or anything else happening elsewhere in the program.
    """
    print("=" * 60)
    # An f-string (the f"..." below) lets us drop a variable's value
    # directly into a text string using curly braces {}.
    print(f"  ACTIVE ORGANIZATION:  {active_tenant_id}")
    print("=" * 60)
    print("  [1] Tokenize Sensitive Data")
    print("  [2] Detokenize a Token")
    print("  [3] Switch Organization")
    print("  [4] Exit Application")
    print("-" * 60)


def handle_tokenize(active_tenant_id):
    """
    Runs the full "Tokenize" workflow: ask for real data, send it to
    the vault UNDER THE CURRENTLY ACTIVE ORGANIZATION, and show the
    user the resulting token.

    "active_tenant_id" is passed IN as a parameter rather than this
    function asking for it itself -- the whole point of this update is
    that we no longer ask "which org?" on every single action. Instead,
    main() (further down) remembers the active org in one variable and
    hands it to whichever function needs it.
    """
    # "input(...)" pauses the program, shows the given prompt text, and
    # waits for the user to type something and press Enter. It always
    # hands back whatever they typed as a string.
    real_data = input("Enter the sensitive data to tokenize (e.g. SSN, card number): ")

    # ".strip()" removes any accidental leading/trailing spaces the
    # user might have typed, so " 123 " and "123" are treated the same.
    real_data = real_data.strip()

    # "if not real_data:" is a common Python idiom. An empty string ""
    # is treated as "falsy," so "not real_data" means "this is empty."
    # We guard against this so we don't store a blank, meaningless entry.
    if not real_data:
        print("\n[!] No data entered. Nothing was tokenized.\n")
        return  # "return" with nothing exits this function immediately.

    # "try / except" is Python's main error-handling tool. Python first
    # attempts everything inside "try:". If ANY error happens during
    # that attempt, instead of crashing the whole program, Python jumps
    # straight into the matching "except:" block below and runs that
    # instead. This is what makes our CLI "robust" rather than fragile.
    try:
        # We pass active_tenant_id straight through as the second
        # argument, matching vault.py's tokenize_data(real_data, tenant_id).
        token = tokenize_data(real_data, active_tenant_id)
        print(f"\n[OK] Success! '{active_tenant_id}' token is:\n     {token}\n")

    # "except Exception as error" catches basically any kind of failure
    # (a database problem, an encryption problem, etc.) and stores the
    # technical details in a variable we named "error", so we can show
    # the user a friendly message instead of a scary crash report.
    except Exception as error:
        print(f"\n[ERROR] Something went wrong while tokenizing: {error}\n")


def handle_detokenize(active_tenant_id):
    """
    Runs the full "Detokenize" workflow: ask for a token, look it up in
    the vault SCOPED TO THE CURRENTLY ACTIVE ORGANIZATION, and show the
    user the original real data -- or a friendly message if that token
    doesn't exist for that organization.
    """
    token = input("Enter the token you want to reverse/look up: ").strip()

    if not token:
        print("\n[!] No token entered. Nothing to look up.\n")
        return

    try:
        # Recall from vault.py: detokenize_data() returns the real
        # string if found FOR THIS ORGANIZATION, or Python's "None"
        # (meaning "nothing") if that token doesn't exist for this
        # tenant_id -- whether because it truly doesn't exist anywhere,
        # OR because it exists but belongs to a DIFFERENT organization.
        # Both cases look identical from here, which is exactly the
        # point: this CLI has no way to even tell the difference, let
        # alone leak one organization's data to another.
        real_data = detokenize_data(token, active_tenant_id)

        # "is None" checks specifically for that "nothing found" case.
        if real_data is None:
            print(f"\n[!] No record found for token {token!r} under organization {active_tenant_id!r}.")
            print("    Double-check the token is correct, or that you're in the right organization.\n")
        else:
            print(f"\n[OK] Token resolved successfully for '{active_tenant_id}':\n     {real_data}\n")

    except Exception as error:
        print(f"\n[ERROR] Something went wrong while detokenizing: {error}\n")


def main():
    """
    The main "traffic controller" of the whole program. This function:
      1. Sets up the database.
      2. Shows the banner and logs the user into an organization.
      3. Runs the menu loop, remembering the active organization in a
         variable for as long as the program keeps running.
    """
    # Make sure the database file and 'tokens' table exist BEFORE we
    # ever show the menu, so options [1] and [2] always have a working
    # database to talk to. Calling this repeatedly is harmless (recall
    # vault.py uses "CREATE TABLE IF NOT EXISTS").
    initialize_database()

    print_banner()

    # NEW: ask for the Organization ID exactly once, right after the
    # banner, before the menu is ever shown. We store the result in
    # this variable -- "active_tenant_id" -- which will stay alive and
    # remembered for as long as the "while True" loop below keeps
    # running, since it's never deleted or overwritten except by the
    # deliberate "Switch Organization" menu option.
    active_tenant_id = ask_for_organization_id("Enter your Organization ID to log in: ")
    print(f"\n[OK] Logged in as organization: '{active_tenant_id}'\n")

    # "while True:" creates a loop that repeats FOREVER -- "True" is a
    # condition that is always, unconditionally true, so the loop never
    # ends on its own. The only way out is something inside the loop
    # explicitly telling Python to stop (we use "break" for that below).
    # This is the standard pattern for "keep showing a menu until the
    # user asks to quit."
    while True:
        # Every time we loop back here, we hand the CURRENT value of
        # active_tenant_id to print_menu(), so the screen always shows
        # whichever organization is presently active -- including
        # right after a deliberate switch (see option "3" below).
        print_menu(active_tenant_id)

        # Ask the user which option they want, and strip stray spaces.
        choice = input("Select an option [1-4]: ").strip()

        # "if / elif / else" is how Python makes decisions. Python checks
        # each condition top to bottom and runs ONLY the first block
        # whose condition is true -- "elif" means "else, if," i.e. "only
        # check this next condition if none of the earlier ones matched."
        if choice == "1":
            # We pass the CURRENT active_tenant_id in as an argument,
            # so handle_tokenize() always uses whichever organization
            # is presently logged in -- it never has to ask itself.
            handle_tokenize(active_tenant_id)

        elif choice == "2":
            handle_detokenize(active_tenant_id)

        elif choice == "3":
            # NEW: "Switch Organization." We simply call our login
            # helper AGAIN and OVERWRITE the active_tenant_id variable
            # with whatever new value comes back. Because Python
            # variables can be reassigned at any time, this is all it
            # takes to "log out and back in" as a different org --
            # no restart of the program required.
            print("\n--- Switch Organization ---")
            active_tenant_id = ask_for_organization_id(
                "Enter the Organization ID to switch to: "
            )
            print(f"\n[OK] Switched active organization to: '{active_tenant_id}'\n")

        elif choice == "4":
            print("\nShutting down Control Panel. Goodbye!\n")
            # "break" immediately stops the nearest enclosing loop --
            # in this case, our "while True" loop -- which is how we
            # let the user cleanly exit the program.
            break

        else:
            # This "else" catches EVERY other possible input: wrong
            # numbers, letters, empty input, emojis, anything. This is
            # exactly the "robust error handling" requirement -- bad
            # input never crashes the program, it just politely
            # complains and loops back to the menu again.
            print(f"\n[!] '{choice}' is not a valid option. Please choose 1, 2, 3, or 4.\n")

        # Note: there's no "return" or "break" down here at the bottom
        # of the loop body (except inside the choice=="4" case above),
        # so after handling whatever the user picked, Python naturally
        # loops back up to "while True:" and shows the menu again --
        # now with whatever active_tenant_id currently holds.

# This special "if" check is a Python convention. It means: "only run
# the code below if this file was run DIRECTLY (e.g. `python main.py`),
# not if it was imported as a helper module into some other file."
if __name__ == "__main__":
    main()
